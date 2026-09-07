//! The flash seq-record codec: two fixed slots of 16 bytes, ping-pong
//! written, CRC-protected — power-loss-safe persistence for the one number
//! a reboot must not lose (the anti-replay mark).
//!
//! Write protocol: read both slots, take the valid record with the higher
//! seq, write the new record to the OTHER slot. A power cut mid-write
//! corrupts at most the slot being written; the previous mark survives in
//! the other. No erase counting or wear levelling — the mark changes once
//! per grant event, thousands of times below any flash endurance concern
//! (stated, not assumed: NOR endurance is ~100k cycles/sector).
//!
//! Pure on purpose: no HAL here, so the codec host-tests in CI while the
//! app crate consumes it on riscv.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

/// One slot: magic(4) ‖ seq(8, LE) ‖ crc32(4, LE, over magic+seq).
pub const SLOT_LEN: usize = 16;
/// Both slots, contiguous.
pub const REGION_LEN: usize = 2 * SLOT_LEN;

const MAGIC: [u8; 4] = *b"LGSQ";

/// Bitwise CRC-32 (IEEE, reflected). Table-free: this runs once per grant
/// event on 12 bytes — size beats speed on a microcontroller.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in bytes {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn encode_slot(seq: u64) -> [u8; SLOT_LEN] {
    let mut slot = [0u8; SLOT_LEN];
    slot[..4].copy_from_slice(&MAGIC);
    slot[4..12].copy_from_slice(&seq.to_le_bytes());
    let crc = crc32(&slot[..12]);
    slot[12..].copy_from_slice(&crc.to_le_bytes());
    slot
}

fn decode_slot(slot: &[u8]) -> Option<u64> {
    if slot.len() != SLOT_LEN || slot[..4] != MAGIC {
        return None;
    }
    let crc = u32::from_le_bytes(slot[12..16].try_into().ok()?);
    if crc32(&slot[..12]) != crc {
        return None;
    }
    Some(u64::from_le_bytes(slot[4..12].try_into().ok()?))
}

/// The stored mark: the valid slot with the higher seq (fresh flash — all
/// 0xff or zeroes — reads as 0).
pub fn read_mark(region: &[u8; REGION_LEN]) -> u64 {
    let a = decode_slot(&region[..SLOT_LEN]);
    let b = decode_slot(&region[SLOT_LEN..]);
    match (a, b) {
        (Some(a), Some(b)) => a.max(b),
        (Some(a), None) => a,
        (None, Some(b)) => b,
        (None, None) => 0,
    }
}

/// Where and what to write for a new mark: the slot index (0 or 1) NOT
/// holding the current best record, and the encoded bytes.
pub fn write_plan(region: &[u8; REGION_LEN], seq: u64) -> (usize, [u8; SLOT_LEN]) {
    let a = decode_slot(&region[..SLOT_LEN]);
    let b = decode_slot(&region[SLOT_LEN..]);
    let target = match (a, b) {
        // Overwrite the invalid or older slot; the current best survives.
        (Some(a_seq), Some(b_seq)) => {
            if a_seq >= b_seq {
                1
            } else {
                0
            }
        }
        (Some(_), None) => 1,
        (None, _) => 0,
    };
    (target, encode_slot(seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mutation notes (each observed failing): drop the CRC check in
    // decode_slot → a_torn_write_leaves_the_previous_mark fails; make
    // write_plan target the SAME slot as the best record → the same test
    // fails (the torn write would destroy the survivor).

    fn region_with(a: Option<u64>, b: Option<u64>) -> [u8; REGION_LEN] {
        let mut region = [0xffu8; REGION_LEN];
        if let Some(seq) = a {
            region[..SLOT_LEN].copy_from_slice(&encode_slot(seq));
        }
        if let Some(seq) = b {
            region[SLOT_LEN..].copy_from_slice(&encode_slot(seq));
        }
        region
    }

    #[test]
    fn fresh_flash_reads_zero() {
        assert_eq!(read_mark(&[0xff; REGION_LEN]), 0);
        assert_eq!(read_mark(&[0x00; REGION_LEN]), 0);
    }

    #[test]
    fn the_higher_valid_seq_wins() {
        assert_eq!(read_mark(&region_with(Some(4), Some(7))), 7);
        assert_eq!(read_mark(&region_with(Some(9), Some(2))), 9);
        assert_eq!(read_mark(&region_with(None, Some(3))), 3);
    }

    #[test]
    fn ping_pong_alternates_and_never_targets_the_best_slot() {
        let mut region = region_with(None, None);
        for seq in 1..=10u64 {
            let (slot, bytes) = write_plan(&region, seq);
            let best_before = read_mark(&region);
            // The survivor property: the slot being written must not hold
            // the current best record.
            if best_before > 0 {
                let survivor = if slot == 0 {
                    &region[SLOT_LEN..]
                } else {
                    &region[..SLOT_LEN]
                };
                assert_eq!(decode_slot(survivor), Some(best_before));
            }
            let start = slot * SLOT_LEN;
            region[start..start + SLOT_LEN].copy_from_slice(&bytes);
            assert_eq!(read_mark(&region), seq);
        }
    }

    #[test]
    fn a_torn_write_leaves_the_previous_mark() {
        // Power cut mid-write: the target slot holds garbage; the mark must
        // still read as the survivor, never as 0 or the torn value.
        let mut region = region_with(Some(5), None);
        let (slot, bytes) = write_plan(&region, 6);
        assert_eq!(slot, 1, "the write must target the non-best slot");
        let start = slot * SLOT_LEN;
        // Half the record lands, then power dies.
        region[start..start + 8].copy_from_slice(&bytes[..8]);
        assert_eq!(read_mark(&region), 5, "the previous mark must survive");
    }

    #[test]
    fn crc_rejects_a_flipped_bit() {
        let mut region = region_with(Some(5), None);
        region[6] ^= 0x01;
        assert_eq!(read_mark(&region), 0, "a corrupt slot must not decode");
    }

    #[test]
    fn crc32_matches_the_ieee_check_value() {
        // The classic "123456789" check value pins the polynomial and
        // reflection conventions against any independent implementation.
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
