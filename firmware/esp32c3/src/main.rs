//! Reference lychgate device firmware for the ESP32-C3.
//!
//! A thin `lychgate-embed` integrator (docs/EMBEDDED.md §11.5): every grant
//! rule lives in the engine this crate shares with the e2e simulator; this
//! file only wires the HAL —
//!
//! - `UptimeClock`  <- the SYSTIMER (52-bit @ 16 MHz, monotonic from boot);
//! - `SeqStore`     <- a 32-byte flash region near the top of the 4 MB part,
//!                     through the pure two-slot codec in the `logic` crate;
//! - `Gate`         <- GPIO4 (the devkit LED header; a relay later), driven
//!                     LOW in main() before the engine even exists — the
//!                     reboot-closes rule, twice over;
//! - the line protocol <- USB-Serial-JTAG (the devkit's USB port).
//!
//! Provisioning: the device identity and the daemon's public key are
//! compile-time constants below for the reference build; a hardened build
//! moves them behind secure boot + flash encryption (docs/EMBEDDED.md §5).
//! Verified by the manual HIL tier (e2e/embedded-hardware.sh) — CI only
//! compiles this crate.

#![no_std]
#![no_main]

use embedded_storage::{ReadStorage, Storage};
use esp_hal::gpio::{Level, Output, OutputConfig};
use esp_hal::main;
use esp_hal::timer::systimer::SystemTimer;
use esp_hal::usb::usb_serial_jtag::UsbSerialJtag;
use esp_storage::FlashStorage;
use lychgate_embed::{DeviceEngine, Gate, SeqStore, StoreError, TrustRoot, UptimeClock};
use lychgate_esp32c3_logic as record;
use lychgate_wire::line;

/// BENCH identity and trust root — replace at provisioning time. The public
/// key matches wire's cap-v1 KAT seed (0x11 * 32), so bench tokens can be
/// minted with `lgcap-sign` out of the box.
const DEVICE_ID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f,
];
const DAEMON_PUBKEY: [u8; 32] = [
    0xd0, 0x4a, 0xb2, 0x32, 0x74, 0x2b, 0xb4, 0xab, 0x3a, 0x13, 0x68, 0xbd, 0x46, 0x15, 0xe4,
    0xe6, 0xd0, 0x22, 0x4a, 0xb7, 0x1a, 0x01, 0x6b, 0xaf, 0x85, 0x20, 0xa3, 0x32, 0xc9, 0x77,
    0x87, 0x37,
];

/// The seq region: the last flash sector of a 4 MB part, far above any
/// partition data this reference image uses.
const SEQ_FLASH_OFFSET: u32 = 0x3f_f000;

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // Fail closed: a panicking device reboots into the closed state.
    esp_hal::system::software_reset()
}

struct SystimerClock;

impl UptimeClock for SystimerClock {
    fn uptime_ms(&self) -> u64 {
        SystemTimer::unit_value(esp_hal::timer::systimer::Unit::Unit0)
            / (SystemTimer::ticks_per_second() / 1000)
    }
}

struct FlashSeq {
    flash: FlashStorage,
}

impl SeqStore for FlashSeq {
    fn load(&mut self) -> Result<u64, StoreError> {
        let mut region = [0u8; record::REGION_LEN];
        self.flash
            .read(SEQ_FLASH_OFFSET, &mut region)
            .map_err(|_| StoreError)?;
        Ok(record::read_mark(&region))
    }

    fn store(&mut self, seq: u64) -> Result<(), StoreError> {
        let mut region = [0u8; record::REGION_LEN];
        self.flash
            .read(SEQ_FLASH_OFFSET, &mut region)
            .map_err(|_| StoreError)?;
        let (slot, bytes) = record::write_plan(&region, seq);
        let offset = SEQ_FLASH_OFFSET + (slot * record::SLOT_LEN) as u32;
        self.flash.write(offset, &bytes).map_err(|_| StoreError)
    }
}

struct GpioGate {
    pin: Output<'static>,
}

impl Gate for GpioGate {
    fn set_open(&mut self, open: bool) {
        self.pin
            .set_level(if open { Level::High } else { Level::Low });
    }
}

#[main]
fn main() -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default());

    // The gate is driven closed before anything else runs — then again by
    // the engine's constructor. Belt and braces on the boot-closes rule.
    let gate_pin = Output::new(peripherals.GPIO4, Level::Low, OutputConfig::default());

    let mut usb = UsbSerialJtag::new(peripherals.USB_DEVICE);

    let mut engine = DeviceEngine::new(
        DEVICE_ID,
        TrustRoot::Ed25519(DAEMON_PUBKEY),
        SystimerClock,
        FlashSeq {
            flash: FlashStorage::new(),
        },
        GpioGate { pin: gate_pin },
    );

    let mut line_buf = [0u8; line::MAX_LINE_LEN];
    let mut reply_buf = [0u8; line::MAX_LINE_LEN];
    let mut len = 0usize;

    loop {
        engine.tick();

        while let Ok(byte) = usb.read_byte() {
            if byte == b'\n' || byte == b'\r' {
                if len > 0 {
                    if let Ok(input) = core::str::from_utf8(&line_buf[..len]) {
                        let reply = engine.handle_line(input, &mut reply_buf);
                        let _ = usb.write(reply.as_bytes());
                        let _ = usb.write(b"\n");
                    } else {
                        let _ = usb.write(b"NAK bad-command\n");
                    }
                    len = 0;
                }
            } else if len < line_buf.len() {
                line_buf[len] = byte;
                len += 1;
            } else {
                // Oversized line: drop it whole rather than act on a prefix.
                len = 0;
                let _ = usb.write(b"NAK bad-command\n");
            }
        }
    }
}
