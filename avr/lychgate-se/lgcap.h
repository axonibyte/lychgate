/* lgcap. v2 payload decoding for tier-A devices: the deterministic-CBOR
 * subset (docs/EMBEDDED.md §11.2), structural checks only. The signature
 * check is DELEGATED — the AVR computes SHA-256("lgcap." ++ payload) with
 * sha256.c and hands digest + raw r||s + the daemon's public key to the
 * ATECC608's Verify command. Ed25519 (v1) is deliberately absent here: it
 * does not fit an ATmega328, which is exactly why v2 exists. */
#ifndef LG_CAP_H
#define LG_CAP_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t ver;
    uint8_t device_id[16];
    uint8_t grant_nonce[16];
    uint32_t capability;
    uint32_t ttl_secs;
    uint64_t issued_seq;
} lg_capability;

/* Decode a capability payload (the raw CBOR bytes, already base64-decoded).
 * Returns 0 on success; nonzero names the first rule broken:
 * 1 truncated/garbage, 2 non-minimal int, 3 wrong key order/size,
 * 4 wrong bstr length, 5 unknown ver, 6 trailing bytes, 7 field overflow. */
int lg_cap_decode(const uint8_t *payload, size_t len, lg_capability *out);

/* SHA-256 of the signed message ("lgcap." ++ payload) — what the SE Verify
 * command takes. */
void lg_cap_signed_digest(const uint8_t *payload, size_t len, uint8_t out[32]);

#endif
