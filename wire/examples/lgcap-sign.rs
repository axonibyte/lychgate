//! Standalone lgcap./lgrvk. signer and verifier for bench work.
//!
//! This is the tool the manual hardware tier (e2e/embedded-hardware.sh) uses
//! to mint tokens for a real device with no daemon in the loop, and a
//! debugging aid for anyone integrating lychgate-embed. Key material arrives
//! as hex on argv because these are throwaway BENCH keys — production tokens
//! are signed only by the daemon, whose key never touches a command line.
//!
//! Usage:
//!   lgcap-sign cap  --seed <64hex>|--scalar <64hex> --device-id <32hex> \
//!       --nonce <32hex> --ttl-secs N --seq N [--capability N]
//!   lgcap-sign rvk  --seed <64hex>|--scalar <64hex> --device-id <32hex> \
//!       --nonce <32hex> --seq N
//!   lgcap-sign public --seed <64hex>|--scalar <64hex>
//!   lgcap-sign verify-cap --public <hex> <token>
//!
//! `--seed` selects v1 (Ed25519), `--scalar` selects v2 (P-256); `public`
//! prints the matching verifier key (raw 32-byte hex, or uncompressed SEC1).

use lychgate_wire::{
    sign_capability_token, sign_revocation_token, verify_capability, Capability, PublicKey,
    Revocation, SigningKey, VER_ED25519, VER_P256,
};

fn die(msg: &str) -> ! {
    eprintln!("lgcap-sign: {msg}");
    std::process::exit(2);
}

fn unhex(s: &str, what: &str) -> Vec<u8> {
    if !s.len().is_multiple_of(2) {
        die(&format!("{what}: odd hex length"));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
                .unwrap_or_else(|_| die(&format!("{what}: not hex")))
        })
        .collect()
}

fn fixed<const N: usize>(s: &str, what: &str) -> [u8; N] {
    unhex(s, what)
        .try_into()
        .unwrap_or_else(|_| die(&format!("{what}: expected {N} bytes of hex")))
}

struct Args(std::collections::BTreeMap<String, String>, Vec<String>);

impl Args {
    fn parse(rest: &[String]) -> Self {
        let mut map = std::collections::BTreeMap::new();
        let mut positional = Vec::new();
        let mut it = rest.iter();
        while let Some(a) = it.next() {
            if let Some(name) = a.strip_prefix("--") {
                let v = it
                    .next()
                    .unwrap_or_else(|| die(&format!("--{name} needs a value")));
                map.insert(name.to_string(), v.clone());
            } else {
                positional.push(a.clone());
            }
        }
        Args(map, positional)
    }

    fn need(&self, name: &str) -> &str {
        self.0
            .get(name)
            .unwrap_or_else(|| die(&format!("missing --{name}")))
    }

    fn num<T: std::str::FromStr>(&self, name: &str, default: Option<T>) -> T {
        match self.0.get(name) {
            Some(v) => v
                .parse()
                .unwrap_or_else(|_| die(&format!("--{name}: not a number"))),
            None => default.unwrap_or_else(|| die(&format!("missing --{name}"))),
        }
    }

    fn key(&self) -> (SigningKey<'_>, u8) {
        match (self.0.get("seed"), self.0.get("scalar")) {
            (Some(_), Some(_)) => die("--seed and --scalar are mutually exclusive"),
            (Some(s), None) => {
                let seed: &'static [u8; 32] = Box::leak(Box::new(fixed::<32>(s, "--seed")));
                (SigningKey::Ed25519Seed(seed), VER_ED25519)
            }
            (None, Some(s)) => {
                let scalar: &'static [u8; 32] = Box::leak(Box::new(fixed::<32>(s, "--scalar")));
                (SigningKey::P256Scalar(scalar), VER_P256)
            }
            (None, None) => die("need --seed (v1/Ed25519) or --scalar (v2/P-256)"),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (mode, rest) = argv
        .split_first()
        .unwrap_or_else(|| die("usage: lgcap-sign cap|rvk|public|verify-cap ..."));
    let args = Args::parse(rest);

    match mode.as_str() {
        "cap" => {
            let (key, ver) = args.key();
            let cap = Capability {
                ver,
                device_id: fixed::<16>(args.need("device-id"), "--device-id"),
                grant_nonce: fixed::<16>(args.need("nonce"), "--nonce"),
                capability: args.num("capability", Some(1)),
                ttl_secs: args.num("ttl-secs", None),
                issued_seq: args.num("seq", None),
            };
            match sign_capability_token(&key, &cap) {
                Ok(t) => println!("{t}"),
                Err(e) => die(&format!("{e}")),
            }
        }
        "rvk" => {
            let (key, ver) = args.key();
            let rvk = Revocation {
                ver,
                device_id: fixed::<16>(args.need("device-id"), "--device-id"),
                grant_nonce: fixed::<16>(args.need("nonce"), "--nonce"),
                issued_seq: args.num("seq", None),
            };
            match sign_revocation_token(&key, &rvk) {
                Ok(t) => println!("{t}"),
                Err(e) => die(&format!("{e}")),
            }
        }
        "public" => match args.key() {
            (SigningKey::Ed25519Seed(seed), _) => {
                let pk = ed25519_dalek::SigningKey::from_bytes(seed).verifying_key();
                println!("{}", hex(&pk.to_bytes()));
            }
            (SigningKey::P256Scalar(scalar), _) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint as _;
                let sk = p256::ecdsa::SigningKey::from_slice(&scalar[..])
                    .unwrap_or_else(|_| die("--scalar: not a valid P-256 scalar"));
                let point = sk.verifying_key().as_affine().to_encoded_point(false);
                println!("{}", hex(point.as_bytes()));
            }
        },
        "verify-cap" => {
            let public = unhex(args.need("public"), "--public");
            let token = args
                .1
                .first()
                .unwrap_or_else(|| die("verify-cap needs the token as a positional argument"));
            let ed_arr: [u8; 32];
            let key = if public.len() == 32 {
                ed_arr = public.clone().try_into().unwrap();
                PublicKey::Ed25519(&ed_arr)
            } else {
                PublicKey::P256Sec1(&public)
            };
            match verify_capability(&key, token) {
                Ok(c) => {
                    println!(
                        "ok ver={} device_id={} nonce={} capability={} ttl_secs={} seq={}",
                        c.ver,
                        hex(&c.device_id),
                        hex(&c.grant_nonce),
                        c.capability,
                        c.ttl_secs,
                        c.issued_seq
                    );
                }
                Err(e) => die(&format!("refused: {e}")),
            }
        }
        other => die(&format!("unknown mode {other}")),
    }
}
