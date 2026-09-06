//! The TSS-backed implementation (feature `tss`).

use anyhow::{anyhow, Context as _, Result};
use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, HashScheme, KeyDerivationFunctionScheme, KeyedHashScheme, Private,
    Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters, SensitiveData,
    SignatureScheme, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::Context;

/// Open a TPM context from a TCTI string (`device:/dev/tpm0`,
/// `swtpm:host=127.0.0.1,port=2321`, `mssim:`, or empty for the default).
pub fn context(tcti: &str) -> Result<Context> {
    let conf: TctiNameConf = tcti
        .parse()
        .map_err(|e| anyhow!("TCTI {tcti:?} did not parse: {e}"))?;
    Context::new(conf).with_context(|| {
        format!("connecting to the TPM via TCTI {tcti:?} — is a TPM 2.0 present and accessible?")
    })
}

/// What `probe` learned about the TPM. Everything lychgate needs is exercised,
/// so a passing probe means register/sign/seal/unseal will work here.
#[derive(Debug)]
pub struct ProbeReport {
    pub manufacturer: String,
    /// The SEC1 public key the signing template derives on THIS TPM.
    pub signing_public_sec1_b64: String,
}

/// The compatibility check: connect, read the manufacturer, derive the signing
/// primary, and round-trip a seal/unseal. A machine may or may not have a
/// TPM — this is how a deployment finds out before trusting one.
pub fn probe(tcti: &str) -> Result<ProbeReport> {
    let mut ctx = context(tcti)?;
    let manufacturer = manufacturer(&mut ctx).unwrap_or_else(|| "(unknown)".to_string());
    let public = signing_public_sec1(&mut ctx)?;
    // Exercise the sealing path end to end so the probe's verdict covers it.
    let blob = seal(&mut ctx, b"lychgate-probe")?;
    let back = unseal(&mut ctx, &blob)?;
    if back != b"lychgate-probe" {
        return Err(anyhow!("seal/unseal round-trip returned different bytes"));
    }
    Ok(ProbeReport {
        manufacturer,
        signing_public_sec1_b64: data_encoding::BASE64URL_NOPAD.encode(&public),
    })
}

fn manufacturer(ctx: &mut Context) -> Option<String> {
    use tss_esapi::constants::property_tag::PropertyTag;
    let raw = ctx.get_tpm_property(PropertyTag::Manufacturer).ok()??;
    let bytes = raw.to_be_bytes();
    Some(
        String::from_utf8_lossy(&bytes)
            .trim_end_matches('\0')
            .to_string(),
    )
}

/// The fixed signing-key template: an owner-hierarchy ECDSA-P256 primary.
/// Re-deriving with this exact template on the same TPM yields the same key,
/// which is why register and sign need no persistent handle.
fn signing_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_sign_encrypt(true)
        .build()
        .context("signing attributes")?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_ecc_scheme(EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)))
                .with_curve(EccCurve::NistP256)
                .with_is_signing_key(true)
                .with_symmetric(SymmetricDefinitionObject::Null)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()
                .context("signing ecc parameters")?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("signing template")
}

/// The fixed storage-parent template for sealing: an owner-hierarchy restricted
/// decryption ECC primary. MUST stay identical between seal and unseal.
fn storage_template() -> Result<Public> {
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .context("storage attributes")?;
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_ecc_parameters(
            PublicEccParametersBuilder::new()
                .with_ecc_scheme(EccScheme::Null)
                .with_curve(EccCurve::NistP256)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_key_derivation_function_scheme(KeyDerivationFunctionScheme::Null)
                .build()
                .context("storage ecc parameters")?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .context("storage template")
}

/// The SEC1 uncompressed public key (0x04‖X‖Y) of this TPM's signing primary —
/// what `lychgate tpm-register` prints for the inventory.
pub fn signing_public_sec1(ctx: &mut Context) -> Result<Vec<u8>> {
    let template = signing_template()?;
    let created = ctx
        .execute_with_nullauth_session(|c| {
            c.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .context("creating the signing primary")?;
    let public = match created.out_public {
        Public::Ecc { unique, .. } => {
            let mut sec1 = vec![0x04u8];
            sec1.extend_from_slice(unique.x().value());
            sec1.extend_from_slice(unique.y().value());
            sec1
        }
        other => return Err(anyhow!("signing primary is not ECC: {other:?}")),
    };
    ctx.flush_context(created.key_handle.into())
        .context("flushing the signing primary")?;
    Ok(public)
}

/// Sign a lychgate challenge with the TPM-resident signing primary, returning
/// the DER ECDSA signature (the payload of an `lgtpm.` token).
pub fn sign_challenge(ctx: &mut Context, challenge: &str) -> Result<Vec<u8>> {
    let digest_bytes = sha2::Sha256::digest(challenge.as_bytes());
    let digest = Digest::try_from(digest_bytes.as_slice()).context("digest")?;
    let template = signing_template()?;
    let created = ctx
        .execute_with_nullauth_session(|c| {
            c.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .context("creating the signing primary")?;
    let validation: tss_esapi::structures::HashcheckTicket = TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: Default::default(),
    }
    .try_into()
    .context("null hashcheck ticket")?;
    let signature = ctx
        .execute_with_nullauth_session(|c| {
            c.sign(
                created.key_handle,
                digest,
                SignatureScheme::Null,
                validation,
            )
        })
        .context("TPM2_Sign")?;
    ctx.flush_context(created.key_handle.into())
        .context("flushing the signing primary")?;
    match signature {
        tss_esapi::structures::Signature::EcDsa(sig) => {
            let r: [u8; 32] = sig
                .signature_r()
                .value()
                .try_into()
                .map_err(|_| anyhow!("signature r is not 32 bytes"))?;
            let s: [u8; 32] = sig
                .signature_s()
                .value()
                .try_into()
                .map_err(|_| anyhow!("signature s is not 32 bytes"))?;
            let der = p256::ecdsa::Signature::from_scalars(r, s)
                .map_err(|e| anyhow!("assembling the ECDSA signature: {e}"))?
                .to_der();
            Ok(der.as_bytes().to_vec())
        }
        other => Err(anyhow!("TPM returned a non-ECDSA signature: {other:?}")),
    }
}

/// A sealed secret: the TPM-wrapped object, storable at rest. Only the TPM that
/// sealed it (via the fixed storage template) can unseal it.
#[derive(Debug, Serialize, Deserialize)]
pub struct SealedBlob {
    pub version: u32,
    /// The sealed object's public area, marshalled, base64url.
    pub public: String,
    /// The sealed object's private area (TPM-encrypted), base64url.
    pub private: String,
}

pub const SEALED_BLOB_VERSION: u32 = 1;

fn storage_parent(ctx: &mut Context) -> Result<tss_esapi::handles::KeyHandle> {
    let template = storage_template()?;
    let created = ctx
        .execute_with_nullauth_session(|c| {
            c.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .context("creating the storage primary")?;
    Ok(created.key_handle)
}

/// Seal `data` to this TPM. The blob is safe to store anywhere; without this
/// physical TPM it is undecryptable.
pub fn seal(ctx: &mut Context, data: &[u8]) -> Result<SealedBlob> {
    let parent = storage_parent(ctx)?;
    let attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()
        .context("sealed-object attributes")?;
    let sealed_public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
        .context("sealed-object template")?;
    let sensitive = SensitiveData::try_from(data.to_vec()).context("secret too large to seal")?;
    let created = ctx
        .execute_with_nullauth_session(|c| {
            c.create(parent, sealed_public, None, Some(sensitive), None, None)
        })
        .context("sealing")?;
    let blob = SealedBlob {
        version: SEALED_BLOB_VERSION,
        public: data_encoding::BASE64URL_NOPAD.encode(
            &created
                .out_public
                .marshall()
                .context("marshalling public")?,
        ),
        private: data_encoding::BASE64URL_NOPAD.encode(created.out_private.as_ref()),
    };
    ctx.flush_context(parent.into())
        .context("flushing the storage primary")?;
    Ok(blob)
}

/// Unseal a blob sealed by `seal` on this same TPM.
pub fn unseal(ctx: &mut Context, blob: &SealedBlob) -> Result<Vec<u8>> {
    if blob.version != SEALED_BLOB_VERSION {
        return Err(anyhow!(
            "sealed blob version {} (this build reads {SEALED_BLOB_VERSION})",
            blob.version
        ));
    }
    let public_bytes = data_encoding::BASE64URL_NOPAD
        .decode(blob.public.as_bytes())
        .map_err(|_| anyhow!("sealed blob public is not base64url"))?;
    let private_bytes = data_encoding::BASE64URL_NOPAD
        .decode(blob.private.as_bytes())
        .map_err(|_| anyhow!("sealed blob private is not base64url"))?;
    let public = Public::unmarshall(&public_bytes).context("unmarshalling public")?;
    let private = Private::try_from(private_bytes).context("private area")?;
    let parent = storage_parent(ctx)?;
    let loaded = ctx
        .execute_with_nullauth_session(|c| c.load(parent, private, public))
        .context("loading the sealed object — sealed on a different TPM?")?;
    let data = ctx
        .execute_with_nullauth_session(|c| c.unseal(loaded.into()))
        .context("unsealing")?;
    ctx.flush_context(parent.into())
        .context("flushing the storage primary")?;
    Ok(data.value().to_vec())
}

/// Serialize / parse a sealed blob file (JSON).
pub fn blob_to_string(blob: &SealedBlob) -> Result<String> {
    serde_json::to_string_pretty(blob).context("encoding the sealed blob")
}
pub fn blob_from_str(text: &str) -> Result<SealedBlob> {
    serde_json::from_str(text).context("parsing the sealed blob")
}
