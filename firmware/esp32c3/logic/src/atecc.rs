//! ATECC608 packet framing — the pure half of the secure-element driver.
//!
//! Everything byte-level lives here (CRC-16, command frames, response
//! parsing) so it host-tests and is shared, via the committed vectors in
//! `wire/vectors/atecc_frame.kat`, with the AVR C library (E7): both I2C
//! stacks must pass identical frames. The I2C transport itself (wake pulse,
//! polling delays) is thin HAL code in the firmware crate, verified at the
//! HIL tier with the real chip.
//!
//! CRC: the ATECC's CRC-16 (polynomial 0x8005, input bits LSB-first, zero
//! seed, transmitted LSB-first). The datasheet-blessed KAT is the wake
//! response `04 11 33 43`: CRC over `04 11` is 0x4333.

/// The device's canonical wake response frame (count, status 0x11, CRC).
pub const WAKE_RESPONSE: [u8; 4] = [0x04, 0x11, 0x33, 0x43];

/// Command opcodes this integration uses. Their parameter semantics are
/// exercised against the real chip at the HIL tier; the framing around them
/// is what these sources guarantee.
pub const OP_INFO: u8 = 0x30;
pub const OP_GENKEY: u8 = 0x40;
pub const OP_NONCE: u8 = 0x16;
pub const OP_SIGN: u8 = 0x41;
pub const OP_READ: u8 = 0x02;

/// The ATECC CRC-16 (Atmel's reference algorithm shape).
pub fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &byte in data {
        for bit in 0..8 {
            let data_bit = (byte >> bit) & 1;
            let crc_bit = (crc >> 15) as u8 & 1;
            crc <<= 1;
            if data_bit ^ crc_bit == 1 {
                crc ^= 0x8005;
            }
        }
    }
    crc
}

/// Build a command frame: `count ‖ opcode ‖ param1 ‖ param2(LE) ‖ data ‖
/// crc(LE)`. The I2C layer prepends the 0x03 word address. Returns the
/// frame length, or None if `out` is too small.
pub fn build_command(
    opcode: u8,
    param1: u8,
    param2: u16,
    data: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let count = 1 + 1 + 1 + 2 + data.len() + 2;
    if count > out.len() || count > u8::MAX as usize {
        return None;
    }
    out[0] = count as u8;
    out[1] = opcode;
    out[2] = param1;
    out[3..5].copy_from_slice(&param2.to_le_bytes());
    out[5..5 + data.len()].copy_from_slice(data);
    let crc = crc16(&out[..count - 2]);
    out[count - 2..count].copy_from_slice(&crc.to_le_bytes());
    Some(count)
}

/// Parse a response frame (count-prefixed, CRC-suffixed), returning the
/// payload. A wrong count or CRC is a refusal, never a shrug.
pub fn parse_response(frame: &[u8]) -> Result<&[u8], AteccFrameError> {
    if frame.len() < 4 {
        return Err(AteccFrameError::Truncated);
    }
    let count = frame[0] as usize;
    if count < 4 || count > frame.len() {
        return Err(AteccFrameError::BadCount);
    }
    let frame = &frame[..count];
    let crc = u16::from_le_bytes([frame[count - 2], frame[count - 1]]);
    if crc16(&frame[..count - 2]) != crc {
        return Err(AteccFrameError::BadCrc);
    }
    Ok(&frame[1..count - 2])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AteccFrameError {
    Truncated,
    BadCount,
    BadCrc,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mutation notes: break crc16's polynomial or bit order → the datasheet
    // wake KAT fails; drop parse_response's CRC check → the corrupt-frame
    // test fails.

    #[test]
    fn the_datasheet_wake_response_is_our_crc_kat() {
        // 04 11 -> 0x4333, transmitted LSB-first as 33 43: the one vector
        // every ATECC integration on earth agrees on.
        assert_eq!(crc16(&WAKE_RESPONSE[..2]), 0x4333);
        assert_eq!(parse_response(&WAKE_RESPONSE).unwrap(), &[0x11]);
    }

    #[test]
    fn a_command_frame_round_trips_through_the_parser() {
        let mut out = [0u8; 96];
        let len = build_command(OP_INFO, 0x00, 0x0000, &[], &mut out).unwrap();
        assert_eq!(len, 7, "INFO carries no data: count+op+p1+p2+crc");
        assert_eq!(out[0], 7);
        // The response parser and the command framer share one CRC.
        assert_eq!(
            parse_response(&out[..len]).unwrap(),
            &[OP_INFO, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn corrupt_frames_are_refused_by_name() {
        let mut frame = WAKE_RESPONSE;
        frame[1] ^= 0x01;
        assert_eq!(parse_response(&frame), Err(AteccFrameError::BadCrc));
        assert_eq!(
            parse_response(&[0x02, 0x00]),
            Err(AteccFrameError::Truncated)
        );
        assert_eq!(
            parse_response(&[0x99, 0x00, 0x00, 0x00]),
            Err(AteccFrameError::BadCount)
        );
    }

    #[test]
    fn frames_match_the_committed_cross_language_vectors() {
        // wire/vectors/atecc_frame.kat is consumed by the AVR C tests too;
        // regenerate deliberately with LYCHGATE_ATECC_REGEN=1.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../wire/vectors/atecc_frame.kat");
        let mut generated = String::from(
            "# ATECC608 framing KAT — shared by the Rust logic crate and the AVR C\n\
             # library. The wake record is datasheet-blessed; command records pin\n\
             # this implementation. Regenerate: LYCHGATE_ATECC_REGEN=1 cargo test.\n\n\
             name = wake-response\nframe = 04113343\npayload = 11\n\n",
        );
        let mut buf = [0u8; 96];
        for (name, op, p1, p2, data) in [
            ("info", OP_INFO, 0x00u8, 0x0000u16, &[][..]),
            ("genkey-slot0", OP_GENKEY, 0x04, 0x0000, &[][..]),
            ("sign-external-slot0", OP_SIGN, 0x80, 0x0000, &[][..]),
            ("nonce-passthrough", OP_NONCE, 0x43, 0x0000, &[0xaa; 32][..]),
        ] {
            let len = build_command(op, p1, p2, data, &mut buf).unwrap();
            let hex: String = buf[..len].iter().map(|b| format!("{b:02x}")).collect();
            generated.push_str(&format!("name = {name}\nframe = {hex}\n\n"));
        }
        if std::env::var_os("LYCHGATE_ATECC_REGEN").is_some() {
            std::fs::write(&path, &generated).unwrap();
            return;
        }
        let committed = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing atecc_frame.kat ({e})"));
        assert_eq!(
            committed, generated,
            "atecc framing drifted from the committed vectors"
        );
    }
}
