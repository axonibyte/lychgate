/* The AVR C library's KAT harness: the SAME committed vectors the Rust
 * crates pin (the .kat files under wire/vectors), same flat format. A C
 * port that passes these speaks the protocol; the format parser is
 * duplicated deliberately (TESTING.md's source-not-re-export rule).
 *
 * Runs on the HOST (make test). The avr-check target only compiles the
 * library objects for atmega328p — proof it fits the tier. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../lgcap.h"
#include "../lggrant.h"
#include "../lghmac.h"
#include "../lgse.h"
#include "../sha256.h"

static int failures = 0;

#define CHECK(cond, ...)                                                       \
    do {                                                                       \
        if (!(cond)) {                                                         \
            failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__);               \
            fprintf(stderr, __VA_ARGS__);                                      \
            fprintf(stderr, "\n");                                             \
        }                                                                      \
    } while (0)

static size_t unhex(const char *hex, uint8_t *out, size_t out_len)
{
    size_t n = strlen(hex) / 2, i;
    if (n > out_len)
        return 0;
    for (i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1)
            return 0;
        out[i] = (uint8_t)v;
    }
    return n;
}

/* --- flat .kat parsing: records of key=value, blank-line separated -------- */

typedef struct {
    char keys[16][32];
    char values[16][512];
    int n;
} record;

static const char *rec_get(const record *r, const char *key)
{
    int i;
    for (i = 0; i < r->n; i++)
        if (strcmp(r->keys[i], key) == 0)
            return r->values[i];
    return NULL;
}

/* Invoke cb for each record in the file; returns the record count. */
static int for_each_record(const char *path, void (*cb)(const record *))
{
    FILE *f = fopen(path, "r");
    char line[600];
    record rec = {.n = 0};
    int count = 0;

    if (!f) {
        fprintf(stderr, "cannot open %s\n", path);
        exit(2);
    }
    for (;;) {
        char *got = fgets(line, sizeof line, f);
        char *eq;
        if (!got || line[0] == '\n') {
            if (rec.n > 0) {
                cb(&rec);
                count++;
                rec.n = 0;
            }
            if (!got)
                break;
            continue;
        }
        if (line[0] == '#')
            continue;
        eq = strchr(line, '=');
        if (!eq || rec.n >= 16)
            continue;
        *eq = '\0';
        /* trim */
        {
            char *k = line, *v = eq + 1, *end;
            while (*k == ' ') k++;
            end = k + strlen(k);
            while (end > k && (end[-1] == ' ')) *--end = '\0';
            while (*v == ' ') v++;
            end = v + strlen(v);
            while (end > v && (end[-1] == '\n' || end[-1] == ' ')) *--end = '\0';
            snprintf(rec.keys[rec.n], sizeof rec.keys[0], "%s", k);
            snprintf(rec.values[rec.n], sizeof rec.values[0], "%s", v);
            rec.n++;
        }
    }
    fclose(f);
    return count;
}

/* --- the tests ------------------------------------------------------------ */

static void nist_sha256_kats(void)
{
    /* FIPS 180-4 / NIST CAVS one-block and two-block message samples. */
    uint8_t d[32];
    uint8_t expect1[32], expect2[32], expect3[32];

    unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          expect1, 32);
    lg_sha256_digest((const uint8_t *)"abc", 3, d);
    CHECK(memcmp(d, expect1, 32) == 0, "sha256(abc)");

    unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          expect2, 32);
    lg_sha256_digest((const uint8_t *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                     56, d);
    CHECK(memcmp(d, expect2, 32) == 0, "sha256(two-block)");

    unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          expect3, 32);
    lg_sha256_digest((const uint8_t *)"", 0, d);
    CHECK(memcmp(d, expect3, 32) == 0, "sha256(empty)");
}

static void atecc_record(const record *r)
{
    const char *frame_hex = rec_get(r, "frame");
    const char *payload_hex = rec_get(r, "payload");
    uint8_t frame[128];
    size_t frame_len = unhex(frame_hex, frame, sizeof frame);
    const uint8_t *payload;
    size_t payload_len;

    CHECK(frame_len > 0, "%s: bad frame hex", rec_get(r, "name"));
    payload_len = lgse_parse_response(frame, frame_len, &payload);
    CHECK(payload_len > 0, "%s: frame did not parse (CRC?)", rec_get(r, "name"));
    if (payload_hex) {
        uint8_t expect[64];
        size_t n = unhex(payload_hex, expect, sizeof expect);
        CHECK(payload_len == n && memcmp(payload, expect, n) == 0,
              "%s: payload mismatch", rec_get(r, "name"));
    }
    /* Corrupt one byte: the frame must be refused. */
    frame[1] ^= 0x01;
    CHECK(lgse_parse_response(frame, frame_len, &payload) == 0,
          "%s: corrupt frame accepted", rec_get(r, "name"));
}

static void hmac_record(const record *r)
{
    uint8_t secret[64];
    size_t secret_len = unhex(rec_get(r, "secret"), secret, sizeof secret);
    char token[LGHMAC_TOKEN_LEN];

    lg_hmac_token(secret, secret_len, rec_get(r, "challenge"), token);
    CHECK(strcmp(token, rec_get(r, "token")) == 0,
          "%s: token mismatch\n  got  %s\n  want %s", rec_get(r, "name"),
          token, rec_get(r, "token"));
}

static void capv2_record(const record *r)
{
    uint8_t payload[80], digest[32], expect[32], id[16];
    size_t len = unhex(rec_get(r, "payload"), payload, sizeof payload);
    lg_capability cap;
    int rc = lg_cap_decode(payload, len, &cap);

    CHECK(rc == 0, "%s: decode failed (%d)", rec_get(r, "name"), rc);
    unhex(rec_get(r, "device_id"), id, 16);
    CHECK(memcmp(cap.device_id, id, 16) == 0, "%s: device_id", rec_get(r, "name"));
    CHECK(cap.ttl_secs == (uint32_t)atoi(rec_get(r, "ttl_secs")), "%s: ttl",
          rec_get(r, "name"));
    CHECK(cap.issued_seq == strtoull(rec_get(r, "issued_seq"), NULL, 10),
          "%s: seq", rec_get(r, "name"));

    /* The digest the SE Verify command takes, pinned by the same record. */
    lg_cap_signed_digest(payload, len, digest);
    unhex(rec_get(r, "signed_sha256"), expect, 32);
    CHECK(memcmp(digest, expect, 32) == 0, "%s: signed digest", rec_get(r, "name"));

    /* Structural refusals. A trailing byte: */
    payload[len] = 0x00;
    CHECK(lg_cap_decode(payload, len + 1, &cap) == 6, "%s: trailing byte",
          rec_get(r, "name"));
    /* And a non-minimal integer: re-encode ver (payload[2], the value of
     * key 0) as the two-byte head 18 02 — same value, wider width, which
     * deterministic CBOR forbids. */
    {
        uint8_t widened[82];
        memcpy(widened, payload, 3);
        widened[2] = 0x18;
        widened[3] = payload[2];
        memcpy(widened + 4, payload + 3, len - 3);
        CHECK(lg_cap_decode(widened, len + 1, &cap) == 2,
              "%s: non-minimal int accepted", rec_get(r, "name"));
    }
}

static void grant_rules(void)
{
    lg_grant g;
    uint8_t nonce[16] = {1};

    lg_grant_init(&g);
    CHECK(g.open == 0, "boot must be closed");
    lg_grant_accept(&g, nonce, 900, 1000);
    CHECK(lg_grant_active(&g, 900999) == 1, "1ms early is open");
    CHECK(lg_grant_active(&g, 901000) == 0, "the deadline closes");
    CHECK(g.open == 0, "closed after expiry");
}

int main(void)
{
    const char *vectors = getenv("LG_VECTORS");
    char path[512];
    int n;

    if (!vectors)
        vectors = "../../wire/vectors";

    nist_sha256_kats();
    grant_rules();

    snprintf(path, sizeof path, "%s/atecc_frame.kat", vectors);
    n = for_each_record(path, atecc_record);
    CHECK(n >= 5, "atecc corpus shrank (%d records)", n);

    snprintf(path, sizeof path, "%s/lghmac_v1.kat", vectors);
    n = for_each_record(path, hmac_record);
    CHECK(n >= 1, "lghmac corpus shrank");

    snprintf(path, sizeof path, "%s/lgcap_v2.kat", vectors);
    n = for_each_record(path, capv2_record);
    CHECK(n >= 3, "lgcap v2 corpus shrank");

    if (failures) {
        fprintf(stderr, "kat_main: %d failure(s)\n", failures);
        return 1;
    }
    printf("kat_main: ok (all shared vectors pass in C)\n");
    return 0;
}
