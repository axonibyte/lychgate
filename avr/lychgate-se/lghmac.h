/* The lghmac device factor: HMAC-SHA256(secret, challenge) as an
 * lghmac.<base64url-nopad> approval token — the mirror of core's
 * hmac_factor, pinned by the same wire/vectors/lghmac_v1.kat. */
#ifndef LG_HMAC_H
#define LG_HMAC_H

#include <stddef.h>
#include <stdint.h>

void lg_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* Render the full token ("lghmac." + base64url-nopad(mac) + NUL).
 * out must hold at least LGHMAC_TOKEN_LEN bytes. */
#define LGHMAC_TOKEN_LEN (7 + 43 + 1)
void lg_hmac_token(const uint8_t *secret, size_t secret_len,
                   const char *challenge, char out[LGHMAC_TOKEN_LEN]);

/* base64url without padding (shared by lghmac and any token rendering). */
size_t lg_b64url(const uint8_t *data, size_t len, char *out, size_t out_len);

#endif
