//! The deterministic CBOR subset the token payloads use — and nothing more.
//!
//! RFC 8949 deterministic encoding, restricted to the only shapes a payload
//! can contain: one top-level map with unsigned-integer keys in strictly
//! ascending order, unsigned-integer values encoded minimally, and
//! fixed-length byte strings. Indefinite lengths, other major types,
//! non-minimal integers, unknown or out-of-order keys, and trailing bytes are
//! all refusals, each with a named reason: a payload has exactly one valid
//! encoding, so signing and re-encoding can never disagree.

use crate::WireError;

const MAJOR_UINT: u8 = 0;
const MAJOR_BSTR: u8 = 2;
const MAJOR_MAP: u8 = 5;

pub(crate) struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Writer { buf, len: 0 }
    }

    pub(crate) fn finish(self) -> usize {
        self.len
    }

    fn push(&mut self, byte: u8) -> Result<(), WireError> {
        if self.len >= self.buf.len() {
            return Err(WireError::BufferTooSmall);
        }
        self.buf[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    /// Major type + minimal-width unsigned argument — the deterministic-CBOR
    /// head encoding.
    fn head(&mut self, major: u8, value: u64) -> Result<(), WireError> {
        let m = major << 5;
        if value < 24 {
            self.push(m | value as u8)
        } else if value <= 0xff {
            self.push(m | 24)?;
            self.push(value as u8)
        } else if value <= 0xffff {
            self.push(m | 25)?;
            for b in (value as u16).to_be_bytes() {
                self.push(b)?;
            }
            Ok(())
        } else if value <= 0xffff_ffff {
            self.push(m | 26)?;
            for b in (value as u32).to_be_bytes() {
                self.push(b)?;
            }
            Ok(())
        } else {
            self.push(m | 27)?;
            for b in value.to_be_bytes() {
                self.push(b)?;
            }
            Ok(())
        }
    }

    pub(crate) fn map(&mut self, entries: u64) -> Result<(), WireError> {
        self.head(MAJOR_MAP, entries)
    }

    pub(crate) fn uint_entry(&mut self, key: u64, value: u64) -> Result<(), WireError> {
        self.head(MAJOR_UINT, key)?;
        self.head(MAJOR_UINT, value)
    }

    pub(crate) fn bstr_entry(&mut self, key: u64, value: &[u8]) -> Result<(), WireError> {
        self.head(MAJOR_UINT, key)?;
        self.head(MAJOR_BSTR, value.len() as u64)?;
        for &b in value {
            self.push(b)?;
        }
        Ok(())
    }
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8, WireError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(WireError::Malformed("truncated"))?;
        self.pos += 1;
        Ok(b)
    }

    /// Read a head, enforcing the minimal-width rule for its argument.
    fn head(&mut self, expect_major: u8, what: &'static str) -> Result<u64, WireError> {
        let initial = self.byte()?;
        if initial >> 5 != expect_major {
            return Err(WireError::Malformed(what));
        }
        let info = initial & 0x1f;
        let value = match info {
            0..=23 => u64::from(info),
            24 => {
                let v = u64::from(self.byte()?);
                if v < 24 {
                    return Err(WireError::Malformed("non-minimal integer"));
                }
                v
            }
            25 => {
                let v = u64::from(u16::from_be_bytes([self.byte()?, self.byte()?]));
                if v <= 0xff {
                    return Err(WireError::Malformed("non-minimal integer"));
                }
                v
            }
            26 => {
                let v = u64::from(u32::from_be_bytes([
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                ]));
                if v <= 0xffff {
                    return Err(WireError::Malformed("non-minimal integer"));
                }
                v
            }
            27 => {
                let v = u64::from_be_bytes([
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                    self.byte()?,
                ]);
                if v <= 0xffff_ffff {
                    return Err(WireError::Malformed("non-minimal integer"));
                }
                v
            }
            // 28–30 are reserved, 31 is an indefinite length.
            _ => return Err(WireError::Malformed("indefinite or reserved length")),
        };
        Ok(value)
    }

    pub(crate) fn map(&mut self, expect_entries: u64) -> Result<(), WireError> {
        let n = self.head(MAJOR_MAP, "not a map")?;
        if n != expect_entries {
            return Err(WireError::Malformed("wrong map size"));
        }
        Ok(())
    }

    fn key(&mut self, expect: u64) -> Result<(), WireError> {
        let k = self.head(MAJOR_UINT, "map key is not an unsigned integer")?;
        if k != expect {
            // Deterministic encoding fixes the key set and order, so any
            // deviation — unknown, duplicate, or reordered — lands here.
            return Err(WireError::Malformed("unexpected map key"));
        }
        Ok(())
    }

    pub(crate) fn uint_entry(&mut self, key: u64, what: &'static str) -> Result<u64, WireError> {
        self.key(key)?;
        self.head(MAJOR_UINT, what)
    }

    pub(crate) fn uint_entry_u32(&mut self, key: u64) -> Result<u32, WireError> {
        let v = self.uint_entry(key, "expected an unsigned integer")?;
        u32::try_from(v).map_err(|_| WireError::Malformed("integer too large for field"))
    }

    pub(crate) fn bstr16_entry(&mut self, key: u64) -> Result<[u8; 16], WireError> {
        self.key(key)?;
        let len = self.head(MAJOR_BSTR, "expected a byte string")?;
        if len != 16 {
            return Err(WireError::Malformed("wrong byte-string length"));
        }
        let mut out = [0u8; 16];
        for slot in &mut out {
            *slot = self.byte()?;
        }
        Ok(out)
    }

    pub(crate) fn end(&self) -> Result<(), WireError> {
        if self.pos != self.buf.len() {
            return Err(WireError::Malformed("trailing bytes"));
        }
        Ok(())
    }
}
