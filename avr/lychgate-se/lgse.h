/* ATECC608 packet framing — the C mirror of the Rust logic crate's atecc
 * module. Both must pass the identical frames in wire/vectors/atecc_frame.kat
 * (the mapping is deliberately duplicated; the shared vectors are the check). */
#ifndef LG_SE_H
#define LG_SE_H

#include <stddef.h>
#include <stdint.h>

#define LGSE_OP_INFO 0x30
#define LGSE_OP_GENKEY 0x40
#define LGSE_OP_NONCE 0x16
#define LGSE_OP_SIGN 0x41
#define LGSE_OP_READ 0x02

/* The datasheet-blessed wake response: count, status 0x11, CRC LSB-first. */
extern const uint8_t LGSE_WAKE_RESPONSE[4];

uint16_t lgse_crc16(const uint8_t *data, size_t len);

/* Build count|op|p1|p2(LE)|data|crc(LE); returns the frame length or 0 if
 * out is too small. The I2C layer prepends the 0x03 word address. */
size_t lgse_build_command(uint8_t opcode, uint8_t param1, uint16_t param2,
                          const uint8_t *data, size_t data_len,
                          uint8_t *out, size_t out_len);

/* Validate a response frame; returns the payload length and sets *payload,
 * or 0 on a bad count/CRC (a corrupt frame is a refusal, not a shrug). */
size_t lgse_parse_response(const uint8_t *frame, size_t frame_len,
                           const uint8_t **payload);

#endif
