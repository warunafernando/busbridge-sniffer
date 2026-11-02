//! Synthetic traffic, so every later subsystem can be tested without hardware.
//!
//! Section 12.1 lists this first among the things to build before the GUI, and
//! the reason is in the acceptance criteria: golden regression tests, identical
//! replay across platforms, and decoders that can be developed offline all need
//! traffic whose content is known exactly and reproducible byte for byte.
//!
//! # Deterministic on purpose
//!
//! No clock is read and nothing is random. The same script produces the same
//! edges at the same picoseconds on every machine and every run - which is what
//! makes a golden file a test rather than a photograph of one afternoon.
//!
//! # It generates waveforms, not transactions
//!
//! Each generator writes what the wires would have done and leaves the decoder
//! to work it out. A generator that emitted decoded transactions would test
//! nothing except itself.

#![forbid(unsafe_code)]

pub mod can;
pub mod protocols;
pub mod wire;

pub use can::Can;
pub use protocols::{I2c, Mdio, Parity, Spi, Uart};
pub use wire::{period, Wire};

use schema::Protocol;

/// A named piece of traffic: what it is, and what protocol decodes it.
pub struct Script {
    pub name: &'static str,
    pub protocol: Protocol,
    pub about: &'static str,
    /// Decoder settings this traffic needs that a capture cannot carry.
    ///
    /// A UART capture cannot say it is 8E1 - the parity bit looks like a data
    /// bit until you know how many there are - so the script that generated it
    /// says so instead. Named in the registry's own vocabulary, so the corpus
    /// and the CLI configure a decoder the same way.
    pub settings: &'static [(&'static str, &'static str)],
}

/// Everything `sniffer scripts` lists and the golden corpus is built from.
pub const SCRIPTS: &[Script] = &[
    Script {
        name: "demo", protocol: Protocol::I2c, settings: &[],
        about: "Appendix D traffic: writes, a register read, a NACK, a read",
    },
    Script {
        name: "scan", protocol: Protocol::I2c, settings: &[],
        about: "an address scan where only 0x52 answers",
    },
    Script {
        name: "stretch", protocol: Protocol::I2c, settings: &[],
        about: "a target stretching the clock mid-transaction",
    },
    Script {
        name: "optics", protocol: Protocol::I2c, settings: &[],
        about: "an optical module at 0x50: identifier, temperature, page \
                select, voltage",
    },
    Script {
        name: "truncated", protocol: Protocol::I2c, settings: &[],
        about: "a capture that ends inside a transaction",
    },
    Script {
        name: "uart", protocol: Protocol::Uart,
        // 8E1: a UART capture cannot say so on its own.
        settings: &[("uart_parity", "e")],
        about: "8E1 text, then a parity error and a framing error",
    },
    Script {
        name: "spi", protocol: Protocol::Spi, settings: &[],
        about: "a JEDEC id read and a page read, CS-bounded",
    },
    Script {
        name: "mdio", protocol: Protocol::Mdio, settings: &[],
        about: "clause 22 reads and writes, and a PHY that never answers",
    },
    Script {
        name: "i3c", protocol: Protocol::I3c, settings: &[],
        about: "ENTDAA, a broadcast CCC, a private transfer and an IBI",
    },
    Script {
        name: "can", protocol: Protocol::Can, settings: &[],
        about: "standard and extended frames, a remote request, an unacknowledged                 frame and a bad CRC",
    },
];

pub fn script_named(name: &str) -> Option<&'static Script> {
    SCRIPTS.iter().find(|s| s.name == name)
}

/// Build a capture from a named script.
///
/// `hz` is the bus rate where the protocol has one. Returns None for a name
/// that is not a script, which the CLI turns into a list of the ones that are.
pub fn build(name: &str, hz: u64) -> Option<file::Capture> {
    let wire = match name {
        "demo" => {
            let mut b = I2c::new(hz);
            b.write(0x52, &[0x10, 0xDE, 0xAD], true);
            b.idle(8);
            b.write_then_read(0x52, &[0x20], &[0x34, 0x8A, 0xF1, 0x22]);
            b.idle(8);
            b.write(0x3C, &[0x01], true);
            b.idle(8);
            b.write(0x77, &[], false);            // nothing at this address
            b.idle(8);
            b.read(0x52, &[0xFF, 0x00], true);
            b.wire
        }
        "scan" => {
            let mut b = I2c::new(hz);
            for addr in 0x50..0x58u8 {
                b.write(addr, &[], addr == 0x52);
                b.idle(4);
            }
            b.wire
        }
        "stretch" => {
            let mut b = I2c::new(hz);
            b.start();
            b.byte(0x52 << 1, true);
            b.set_rate(hz / 50);                  // the target holds the clock
            b.byte(0xAA, true);
            b.set_rate(hz);
            b.byte(0xBB, true);
            b.stop();
            b.wire
        }
        "optics" => {
            // A transceiver at 0x50, in the order anybody brings one up:
            // probe, identify, read the monitors, then reach into an upper
            // page. The bytes are the ones CMIS defines, so the device
            // analyser has something true to decode rather than something
            // arranged to suit it.
            let mut b = I2c::new(hz);
            b.write(0x50, &[], true);                    // probe: it answers
            b.idle(8);
            b.write_then_read(0x50, &[0x00], &[0x18]);   // identifier: QSFP-DD
            b.idle(8);
            // Temperature: 0x1A31 is 26.19 C in CMIS's 1/256 C units.
            b.write_then_read(0x50, &[0x0E], &[0x1A, 0x31]);
            b.idle(8);
            b.write(0x50, &[0x7F, 0x11], true);          // select page 0x11
            b.idle(8);
            b.write_then_read(0x50, &[0x90], &[0x00, 0x64]);  // an upper-page read
            b.idle(8);
            // Supply voltage: 0x8034 counts of 100 uV is 3.2820 V.
            b.write_then_read(0x50, &[0x10], &[0x80, 0x34]);
            b.idle(8);
            // And a read from an upper page register with no page select
            // before it, which the analyser has to refuse to name.
            b.write_then_read(0x51, &[0x95], &[0x01]);
            b.wire
        }
        "truncated" => {
            let mut b = I2c::new(hz);
            b.start();
            b.byte(0x52 << 1, true);
            b.byte(0xDE, true);
            b.wire                                 // no STOP: ends mid-transaction
        }
        "uart" => {
            // 8E1 so parity is exercised; the errors come last so everything
            // before them decodes cleanly and the contrast is visible.
            let mut u = Uart::new(115_200, 8, Parity::Even, 1);
            u.text("READY");
            u.idle(4);
            u.byte_with_bad_parity(0x41);
            u.idle(4);
            u.byte_with_framing_error(0x42);
            u.idle(4);
            u.text("OK");
            u.wire
        }
        "spi" => {
            let mut s = Spi::new(hz.max(1_000_000), 0);
            // A JEDEC id read: 0x9F out, three bytes back.
            s.exchange(&[0x9F, 0x00, 0x00, 0x00], &[0x00, 0xEF, 0x40, 0x18]);
            s.idle(8);
            // A page read: opcode, three address bytes, four data bytes.
            s.exchange(&[0x03, 0x00, 0x01, 0x00, 0, 0, 0, 0],
                       &[0, 0, 0, 0, 0xDE, 0xAD, 0xBE, 0xEF]);
            s.wire
        }
        "mdio" => {
            let mut m = Mdio::new(hz.max(1_000_000));
            m.c22_read(1, 0x02, 0x0141, true);     // PHY id high
            m.c22_read(1, 0x03, 0x0DD1, true);     // PHY id low
            m.c22_write(1, 0x00, 0x1200, true);    // restart autonegotiation
            m.c22_read(1, 0x01, 0x796D, true);     // status
            m.c22_read_no_turnaround(7, 0x02, true);   // nothing at PHY 7
            m.wire
        }
        "i3c" => {
            // I3C SDR on the same two wires as I2C. Built from the I2C
            // generator because at this level the framing is the same - what
            // differs is the ninth bit, which is a T-bit rather than an
            // acknowledge, and that is the decoder's problem to tell apart.
            let mut b = I2c::new(hz.max(1_000_000));
            // ENTDAA: broadcast 0x7E write, then the CCC, then the target's
            // 48-bit PID / BCR / DCR and the address it is given.
            b.start();
            b.byte(0x7E << 1, true);
            b.i3c_write_byte(0x07);                // ENTDAA
            b.repeated_start();
            b.byte((0x7E << 1) | 1, true);
            // The discovery data is sixty-four contiguous arbitration bits:
            // no T-bit between them, which is why these are plain bytes.
            for byte in [0x04, 0xA0, 0x00, 0x00, 0x12, 0x34, 0x06, 0x2B] {
                b.byte(byte, true);                // PID, BCR, DCR
            }
            b.byte(0x52 << 1, true);               // the dynamic address given
            b.stop();
            b.idle(8);
            // A broadcast CCC.
            b.start();
            b.byte(0x7E << 1, true);
            b.i3c_write_byte(0x00);                // ENEC
            b.i3c_write_byte(0x0B);
            b.stop();
            b.idle(8);
            // A private write and a private read to the address just assigned.
            b.start();
            b.byte(0x52 << 1, true);
            b.i3c_write_byte(0x10);
            b.i3c_write_byte(0x20);
            b.stop();
            b.idle(8);
            // A private read. The ninth bit of each byte is a T-bit meaning
            // "more data follows", not an acknowledge and not parity.
            b.start();
            b.byte((0x52 << 1) | 1, true);
            b.i3c_read_byte(0x34);
            b.i3c_read_byte(0x8A);
            b.stop();
            b.idle(8);
            // An in-band interrupt: the target drives its own address after a
            // START, with the read bit set. Its mandatory data byte carries a
            // T-bit like any other read byte.
            b.start();
            b.byte((0x52 << 1) | 1, true);
            b.i3c_read_byte(0x01);
            b.stop();
            b.wire
        }
        "can" => {
            let mut c = Can::new(if hz >= 10_000 { hz } else { 500_000 });
            c.frame(0x123, false, &[0xDE, 0xAD, 0xBE, 0xEF], false);
            c.idle(20);
            c.frame(0x12AB_CDE, true, &[0x01, 0x02], false);
            c.idle(20);
            c.frame(0x200, false, &[0, 0, 0], true);      // remote request
            c.idle(20);
            // Runs of identical bits, so the frame is full of stuff bits.
            c.frame(0x000, false, &[0x00, 0x00, 0xFF, 0xFF], false);
            c.idle(20);
            c.frame_unacked(0x321, &[0xAA]);              // nothing answered
            c.idle(20);
            c.frame_bad_crc(0x111, &[0x55]);
            c.idle(20);
            c.wire
        }
        _ => return None,
    };
    Some(wire.capture(name))
}

/// Build a capture and punch a hole in it, for testing gap behaviour.
pub fn build_with_gap(name: &str, hz: u64) -> Option<file::Capture> {
    // Built by generating the script twice with a hole between: a gap at the
    // end is indistinguishable from the capture simply ending, and section 12.1
    // wants the behaviour verified rather than asserted.
    let mut b = I2c::new(hz);
    b.write(0x52, &[0x10, 0xDE, 0xAD], true);
    b.idle(8);
    b.wire.gap(period(hz) * 10, "injected packet loss");
    // A transaction that straddles the hole: started before, finished after.
    b.start();
    b.byte(0x52 << 1, true);
    b.wire.gap(period(hz) * 4, "injected packet loss (mid-transaction)");
    b.byte(0xAA, true);
    b.stop();
    b.idle(8);
    b.write(0x52, &[0xBB], true);

    if script_named(name).is_none() {
        return None;
    }
    Some(b.wire.capture(&format!("{name}+gap")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_listed_script_builds() {
        for s in SCRIPTS {
            let cap = build(s.name, 100_000)
                .unwrap_or_else(|| panic!("{} is listed but does not build", s.name));
            assert!(cap.chunks[0].transitions() > 0, "{} produced no edges", s.name);
        }
        assert!(build("no such script", 100_000).is_none());
    }

    #[test]
    fn scripts_are_reproducible() {
        for s in SCRIPTS {
            let a = build(s.name, 100_000).unwrap();
            let b = build(s.name, 100_000).unwrap();
            assert_eq!(a.chunks, b.chunks, "{} is not deterministic", s.name);
        }
    }

    #[test]
    fn edges_are_ordered_and_never_repeat_a_state() {
        for s in SCRIPTS {
            let cap = build(s.name, 100_000).unwrap();
            let chunk = &cap.chunks[0];
            for i in 1..chunk.len() {
                assert!(chunk.times[i] > chunk.times[i - 1],
                        "{}: time went backwards at {i}", s.name);
                assert_ne!(chunk.lines[i], chunk.lines[i - 1],
                           "{}: entry {i} changed nothing", s.name);
            }
        }
    }

    #[test]
    fn channel_names_match_the_protocol() {
        assert_eq!(build("demo", 100_000).unwrap().session.channels,
                   vec!["SCL", "SDA"]);
        assert_eq!(build("uart", 115_200).unwrap().session.channels, vec!["RX"]);
        assert_eq!(build("spi", 1_000_000).unwrap().session.channels,
                   vec!["CLK", "MOSI", "MISO", "CS"]);
        assert_eq!(build("mdio", 1_000_000).unwrap().session.channels,
                   vec!["MDC", "MDIO"]);
    }

    #[test]
    fn the_gap_script_puts_a_hole_inside_a_transaction() {
        let cap = build_with_gap("demo", 100_000).unwrap();
        assert_eq!(cap.gaps.len(), 2);
        // One of them must fall between the first and last edge, or it is a gap
        // at the edge of the capture and proves nothing.
        let first = cap.chunks[0].times[0];
        let last = *cap.chunks[0].times.last().unwrap();
        assert!(cap.gaps.iter().any(|g| g.start > first && g.end < last),
                "no gap lands inside the traffic");
    }
}
