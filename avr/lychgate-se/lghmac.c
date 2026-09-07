#include "lghmac.h"

#include <string.h>

#include "sha256.h"

void lg_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len, uint8_t out[32])
{
    uint8_t k[64];
    uint8_t pad[64];
    uint8_t inner[32];
    lg_sha256 ctx;
    int i;

    memset(k, 0, sizeof k);
    if (key_len > 64) {
        lg_sha256_digest(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    for (i = 0; i < 64; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    lg_sha256_init(&ctx);
    lg_sha256_update(&ctx, pad, 64);
    lg_sha256_update(&ctx, msg, msg_len);
    lg_sha256_final(&ctx, inner);

    for (i = 0; i < 64; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    lg_sha256_init(&ctx);
    lg_sha256_update(&ctx, pad, 64);
    lg_sha256_update(&ctx, inner, 32);
    lg_sha256_final(&ctx, out);
}

static const char B64URL[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

size_t lg_b64url(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    size_t written = 0;
    size_t i;

    for (i = 0; i < len; i += 3) {
        uint32_t chunk = (uint32_t)data[i] << 16;
        size_t have = len - i;
        size_t emit = (have >= 3) ? 4 : have + 1;
        size_t j;

        if (have > 1)
            chunk |= (uint32_t)data[i + 1] << 8;
        if (have > 2)
            chunk |= (uint32_t)data[i + 2];
        for (j = 0; j < emit; j++) {
            if (written >= out_len)
                return 0;
            out[written++] = B64URL[(chunk >> (18 - 6 * j)) & 0x3f];
        }
    }
    return written;
}

void lg_hmac_token(const uint8_t *secret, size_t secret_len,
                   const char *challenge, char out[LGHMAC_TOKEN_LEN])
{
    uint8_t mac[32];
    size_t n;

    lg_hmac_sha256(secret, secret_len, (const uint8_t *)challenge,
                   strlen(challenge), mac);
    memcpy(out, "lghmac.", 7);
    n = lg_b64url(mac, 32, out + 7, LGHMAC_TOKEN_LEN - 8);
    out[7 + n] = '\0';
}
