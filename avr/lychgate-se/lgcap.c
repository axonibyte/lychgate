#include "lgcap.h"

#include <string.h>

#include "sha256.h"

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
} reader;

static int rd_byte(reader *r, uint8_t *out)
{
    if (r->pos >= r->len)
        return 1;
    *out = r->buf[r->pos++];
    return 0;
}

/* Read a head of the expected major type, enforcing minimal-width ints. */
static int rd_head(reader *r, uint8_t expect_major, uint64_t *value)
{
    uint8_t initial, info, b;
    uint64_t v = 0;
    int i, width;

    if (rd_byte(r, &initial))
        return 1;
    if ((initial >> 5) != expect_major)
        return 3;
    info = initial & 0x1f;
    if (info < 24) {
        *value = info;
        return 0;
    }
    if (info == 24)
        width = 1;
    else if (info == 25)
        width = 2;
    else if (info == 26)
        width = 4;
    else if (info == 27)
        width = 8;
    else
        return 1; /* indefinite/reserved */
    for (i = 0; i < width; i++) {
        if (rd_byte(r, &b))
            return 1;
        v = (v << 8) | b;
    }
    /* Minimal-width rule: the value must not fit the next narrower head. */
    if ((width == 1 && v < 24) || (width == 2 && v <= 0xff) ||
        (width == 4 && v <= 0xffff) || (width == 8 && v <= 0xffffffffu))
        return 2;
    *value = v;
    return 0;
}

static int rd_uint_entry(reader *r, uint64_t key, uint64_t *value)
{
    uint64_t k;
    int rc;

    if ((rc = rd_head(r, 0, &k)) != 0)
        return rc;
    if (k != key)
        return 3;
    return rd_head(r, 0, value);
}

static int rd_bstr16_entry(reader *r, uint64_t key, uint8_t out[16])
{
    uint64_t k, len;
    int rc, i;
    uint8_t b;

    if ((rc = rd_head(r, 0, &k)) != 0)
        return rc;
    if (k != key)
        return 3;
    if ((rc = rd_head(r, 2, &len)) != 0)
        return rc;
    if (len != 16)
        return 4;
    for (i = 0; i < 16; i++) {
        if (rd_byte(r, &b))
            return 1;
        out[i] = b;
    }
    return 0;
}

int lg_cap_decode(const uint8_t *payload, size_t len, lg_capability *out)
{
    reader r = {payload, len, 0};
    uint64_t map_len, v;
    int rc;

    if ((rc = rd_head(&r, 5, &map_len)) != 0)
        return rc;
    if (map_len != 6)
        return 3;
    if ((rc = rd_uint_entry(&r, 0, &v)) != 0)
        return rc;
    if (v != 2)
        return 5; /* only v2 is SE-verifiable on this tier */
    out->ver = (uint8_t)v;
    if ((rc = rd_bstr16_entry(&r, 1, out->device_id)) != 0)
        return rc;
    if ((rc = rd_bstr16_entry(&r, 2, out->grant_nonce)) != 0)
        return rc;
    if ((rc = rd_uint_entry(&r, 3, &v)) != 0)
        return rc;
    if (v > 0xffffffffu)
        return 7;
    out->capability = (uint32_t)v;
    if ((rc = rd_uint_entry(&r, 4, &v)) != 0)
        return rc;
    if (v > 0xffffffffu)
        return 7;
    out->ttl_secs = (uint32_t)v;
    if ((rc = rd_uint_entry(&r, 5, &out->issued_seq)) != 0)
        return rc;
    if (r.pos != r.len)
        return 6;
    return 0;
}

void lg_cap_signed_digest(const uint8_t *payload, size_t len, uint8_t out[32])
{
    lg_sha256 ctx;
    lg_sha256_init(&ctx);
    lg_sha256_update(&ctx, (const uint8_t *)"lgcap.", 6);
    lg_sha256_update(&ctx, payload, len);
    lg_sha256_final(&ctx, out);
}
