//! The ATECC608 secure-element integration (`se` feature): the thin I2C
//! transport under the pure framing in the logic crate, and the two
//! ceremonies the SE-PUBKEY?/SE-SIGN protocol commands need.
//!
//! Everything byte-exact is KAT'd in the logic crate; what lives here is
//! the part only a real chip can prove — wake timing, polling delays,
//! command execution — and it is verified at the HIL tier
//! (e2e/embedded-hardware.sh with an ATECC608 wired to GPIO2/GPIO3).
//! The key ceremony (docs/EMBEDDED.md §5): the private key is generated IN
//! the chip's slot 0 and never leaves it; SE-PUBKEY? derives the public
//! half, SE-SIGN hashes the challenge on this MCU and has the chip sign
//! the digest, emitting a standard `lgtpm.` approval token (the daemon's
//! existing tpm kind verifies it — zero engine changes).

use esp_hal::delay::Delay;
use esp_hal::i2c::master::I2c;
use esp_hal::Blocking;
use lychgate_esp32c3_logic::atecc;

/// The ATECC608's 7-bit I2C address (0xC0 >> 1, the family default).
const ADDR: u8 = 0x60;
/// Word addresses: reset the read pointer / send a command.
const WORD_ADDR_COMMAND: u8 = 0x03;
/// Key slot holding the device's P-256 identity.
const KEY_SLOT: u16 = 0;

pub struct Atecc {
    i2c: I2c<'static, Blocking>,
    delay: Delay,
}

#[derive(Debug, Clone, Copy)]
pub enum SeError {
    Bus,
    Frame,
    Status(u8),
}

impl Atecc {
    pub fn new(i2c: I2c<'static, Blocking>) -> Self {
        Atecc {
            i2c,
            delay: Delay::new(),
        }
    }

    /// Wake the chip: a general-call zero byte holds SDA low long enough at
    /// 100 kHz, then the canonical wake response is read back and CHECKED —
    /// a chip that does not answer 04 11 33 43 is not treated as awake.
    fn wake(&mut self) -> Result<(), SeError> {
        // The write is expected to NACK (address 0x00); the pulse is the point.
        let _ = self.i2c.write(0x00u8, &[0x00]);
        self.delay.delay_micros(1500);
        let mut response = [0u8; 4];
        self.i2c
            .read(ADDR, &mut response)
            .map_err(|_| SeError::Bus)?;
        if response != atecc::WAKE_RESPONSE {
            return Err(SeError::Frame);
        }
        Ok(())
    }

    /// Send one command frame and read its response payload.
    fn command(
        &mut self,
        opcode: u8,
        param1: u8,
        param2: u16,
        data: &[u8],
        exec_ms: u32,
        out: &mut [u8],
    ) -> Result<usize, SeError> {
        let mut frame = [0u8; 96];
        let len =
            atecc::build_command(opcode, param1, param2, data, &mut frame).ok_or(SeError::Frame)?;
        let mut wire = [0u8; 97];
        wire[0] = WORD_ADDR_COMMAND;
        wire[1..1 + len].copy_from_slice(&frame[..len]);
        self.i2c
            .write(ADDR, &wire[..1 + len])
            .map_err(|_| SeError::Bus)?;
        self.delay.delay_millis(exec_ms);

        let mut response = [0u8; 96];
        self.i2c
            .read(ADDR, &mut response)
            .map_err(|_| SeError::Bus)?;
        let payload = atecc::parse_response(&response).map_err(|_| SeError::Frame)?;
        // A 1-byte payload is a status code; 0x00 is success-with-no-data,
        // anything else is the chip refusing.
        if payload.len() == 1 && payload[0] != 0x00 {
            return Err(SeError::Status(payload[0]));
        }
        if payload.len() > out.len() {
            return Err(SeError::Frame);
        }
        out[..payload.len()].copy_from_slice(payload);
        Ok(payload.len())
    }

    /// The public half of slot 0's P-256 key (64 bytes, X ‖ Y).
    pub fn public_key(&mut self) -> Result<[u8; 64], SeError> {
        self.wake()?;
        let mut out = [0u8; 64];
        // GenKey mode 0x00: derive and return the public key of an existing
        // private key (no regeneration).
        let n = self.command(atecc::OP_GENKEY, 0x00, KEY_SLOT, &[], 120, &mut out)?;
        if n != 64 {
            return Err(SeError::Frame);
        }
        Ok(out)
    }

    /// Sign a 32-byte digest with slot 0: Nonce (pass-through into TempKey)
    /// then Sign (external message mode). Returns the raw r ‖ s signature.
    pub fn sign_digest(&mut self, digest: &[u8; 32]) -> Result<[u8; 64], SeError> {
        self.wake()?;
        let mut scratch = [0u8; 64];
        self.command(atecc::OP_NONCE, 0x43, 0x0000, digest, 30, &mut scratch)?;
        let mut sig = [0u8; 64];
        let n = self.command(atecc::OP_SIGN, 0x80, KEY_SLOT, &[], 120, &mut sig)?;
        if n != 64 {
            return Err(SeError::Frame);
        }
        Ok(sig)
    }
}
