#include "lggrant.h"

#include <string.h>

void lg_grant_init(lg_grant *g)
{
    memset(g, 0, sizeof *g);
}

void lg_grant_accept(lg_grant *g, const uint8_t nonce[16], uint32_t ttl_secs,
                     uint32_t now_ms)
{
    memcpy(g->nonce, nonce, 16);
    g->expires_at_ms = now_ms + ttl_secs * 1000u;
    g->open = 1;
}

uint8_t lg_grant_active(lg_grant *g, uint32_t now_ms)
{
    if (!g->open)
        return 0;
    /* Unsigned wrap-safe compare: the deadline is at most 24h out. */
    if ((uint32_t)(g->expires_at_ms - now_ms) > 0x80000000u || g->expires_at_ms == now_ms) {
        lg_grant_close(g);
        return 0;
    }
    return 1;
}

void lg_grant_close(lg_grant *g)
{
    g->open = 0;
    memset(g->nonce, 0, sizeof g->nonce);
}
