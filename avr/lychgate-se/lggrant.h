/* Uptime-anchored grant state for a tier-A device — the C mirror of the
 * lychgate-embed engine's core rules, sized for 2 KB of RAM. RAM-only by
 * construction: a reboot loses the struct, which IS the boot-closes rule.
 * The seq mark's persistence is the integrator's (EEPROM on an AVR). */
#ifndef LG_GRANT_H
#define LG_GRANT_H

#include <stdint.h>

typedef struct {
    uint8_t open;             /* the gate line mirrors this */
    uint8_t nonce[16];
    uint32_t expires_at_ms;   /* uptime deadline; 32-bit wraps at ~49 days,
                                 far beyond the 24h TTL cap */
} lg_grant;

/* Boot state: closed. Call before anything else. */
void lg_grant_init(lg_grant *g);

/* Accept a verified capability: anchors ttl_secs at now_ms. The CALLER has
 * already checked signature, device id, seq and the TTL cap. */
void lg_grant_accept(lg_grant *g, const uint8_t nonce[16], uint32_t ttl_secs,
                     uint32_t now_ms);

/* Expiry is a property of observation: returns 1 while open, dropping the
 * grant the moment now_ms passes the deadline. */
uint8_t lg_grant_active(lg_grant *g, uint32_t now_ms);

void lg_grant_close(lg_grant *g);

#endif
