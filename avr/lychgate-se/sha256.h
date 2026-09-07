/* SHA-256, implemented from FIPS 180-4 for the tier-A build (no RustCrypto
 * exists for AVR C). "Hand-carried, not hand-rolled" in the honest sense the
 * docs give it: the implementation is the standard algorithm verbatim, and
 * the NIST KATs in the test binary are what make it trustworthy — a digest
 * implementation that passes them byte-for-byte is the algorithm. */
#ifndef LG_SHA256_H
#define LG_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t length_bits;
    uint8_t buffer[64];
    size_t buffered;
} lg_sha256;

void lg_sha256_init(lg_sha256 *ctx);
void lg_sha256_update(lg_sha256 *ctx, const uint8_t *data, size_t len);
void lg_sha256_final(lg_sha256 *ctx, uint8_t out[32]);
void lg_sha256_digest(const uint8_t *data, size_t len, uint8_t out[32]);

#endif
