#include "lgse.h"

const uint8_t LGSE_WAKE_RESPONSE[4] = {0x04, 0x11, 0x33, 0x43};

uint16_t lgse_crc16(const uint8_t *data, size_t len)
{
    uint16_t crc = 0;
    size_t i;
    int bit;

    for (i = 0; i < len; i++) {
        for (bit = 0; bit < 8; bit++) {
            uint8_t data_bit = (uint8_t)((data[i] >> bit) & 1);
            uint8_t crc_bit = (uint8_t)((crc >> 15) & 1);
            crc = (uint16_t)(crc << 1);
            if ((data_bit ^ crc_bit) == 1)
                crc ^= 0x8005;
        }
    }
    return crc;
}

size_t lgse_build_command(uint8_t opcode, uint8_t param1, uint16_t param2,
                          const uint8_t *data, size_t data_len,
                          uint8_t *out, size_t out_len)
{
    size_t count = 1 + 1 + 1 + 2 + data_len + 2;
    uint16_t crc;
    size_t i;

    if (count > out_len || count > 255)
        return 0;
    out[0] = (uint8_t)count;
    out[1] = opcode;
    out[2] = param1;
    out[3] = (uint8_t)(param2 & 0xff);
    out[4] = (uint8_t)(param2 >> 8);
    for (i = 0; i < data_len; i++)
        out[5 + i] = data[i];
    crc = lgse_crc16(out, count - 2);
    out[count - 2] = (uint8_t)(crc & 0xff);
    out[count - 1] = (uint8_t)(crc >> 8);
    return count;
}

size_t lgse_parse_response(const uint8_t *frame, size_t frame_len,
                           const uint8_t **payload)
{
    size_t count;
    uint16_t crc;

    if (frame_len < 4)
        return 0;
    count = frame[0];
    if (count < 4 || count > frame_len)
        return 0;
    crc = (uint16_t)(frame[count - 2] | ((uint16_t)frame[count - 1] << 8));
    if (lgse_crc16(frame, count - 2) != crc)
        return 0;
    *payload = frame + 1;
    return count - 3;
}
