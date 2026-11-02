//! CAN traffic, bit by bit.
//!
//! The two rules a generator has to get right, because a decoder tested against
//! one that skipped them would pass here and fail on a wire:
//!
//! **Bit stuffing.** After five identical bits the transmitter inserts one of
//! the opposite value, from the start of frame through the end of the CRC. It
//! is not optional and it is not decoration: it is how receivers stay
//! synchronised on a bus with no clock line, and it means the number of bits on
//! the wire is not the number of bits in the frame.
//!
//! **CRC-15.** Polynomial 0x4599 over the *destuffed* bits from SOF through the
//! end of the data field. Computed here properly so a decoder that computes it
//! wrongly fails a test rather than agreeing with a shared mistake.
//!
//! One channel, idling recessive. Dominant is 0 and is the level a node drives;
//! recessive is 1 and is what the bus rests at.

use crate::wire::{period, Wire};
use schema::Picos;

/// The CAN CRC-15 polynomial.
const CRC15_POLY: u16 = 0x4599;

/// CRC-15 over a sequence of bits, as CAN defines it.
pub fn crc15(bits: &[bool]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bits {
        let top = (crc >> 14) & 1 == 1;
        crc = (crc << 1) & 0x7FFF;
        if top != b {
            crc ^= CRC15_POLY;
        }
    }
    crc & 0x7FFF
}

/// A frame under construction, before stuffing.
struct Raw {
    bits: Vec<bool>,
}

impl Raw {
    fn new() -> Self {
        Raw { bits: Vec::new() }
    }

    fn bit(&mut self, v: bool) {
        self.bits.push(v);
    }

    fn field(&mut self, value: u32, count: u8) {
        for i in (0..count).rev() {
            self.bit(value & (1 << i) != 0);
        }
    }
}

/// Insert a stuff bit after every five identical bits.
///
/// Returns the wire sequence. The caller appends everything from the CRC
/// delimiter onwards afterwards, because stuffing stops there.
pub fn stuff(bits: &[bool]) -> Vec<bool> {
    let mut out = Vec::with_capacity(bits.len() + bits.len() / 5);
    let mut run = 0u8;
    let mut last = None;

    for &b in bits {
        if Some(b) == last {
            run += 1;
        } else {
            run = 1;
            last = Some(b);
        }
        out.push(b);
        if run == 5 {
            out.push(!b);
            last = Some(!b);
            run = 1;
        }
    }
    out
}

pub struct Can {
    pub wire: Wire,
    bit_ps: Picos,
}

impl Can {
    /// `bitrate` in bits per second: 500_000 is the commonest.
    pub fn new(bitrate: u64) -> Self {
        let bit_ps = period(bitrate);
        // One channel, idling recessive.
        Can { wire: Wire::new(&["CAN"], 0b1, bit_ps), bit_ps }
    }

    fn emit(&mut self, bits: &[bool]) {
        for &b in bits {
            self.wire.advance(self.bit_ps);
            self.wire.set(0, b);
        }
        // To the end of the last bit, so the capture does not appear to stop
        // inside it - the same rule the UART generator follows.
        self.wire.advance(self.bit_ps);
    }

    /// Time passes with the bus idle.
    pub fn idle(&mut self, bits: u64) {
        self.wire.set(0, true);
        self.wire.advance(self.bit_ps * bits);
    }

    /// A standard (11-bit) or extended (29-bit) data or remote frame.
    pub fn frame(&mut self, id: u32, extended: bool, data: &[u8], remote: bool) {
        let mut raw = Raw::new();
        raw.bit(false);                              // SOF, dominant

        if extended {
            raw.field(id >> 18, 11);                 // ID A
            raw.bit(true);                           // SRR, recessive
            raw.bit(true);                           // IDE, recessive
            raw.field(id & 0x3FFFF, 18);             // ID B
            raw.bit(remote);                         // RTR
            raw.bit(false);                          // r1
            raw.bit(false);                          // r0
        } else {
            raw.field(id & 0x7FF, 11);
            raw.bit(remote);                         // RTR
            raw.bit(false);                          // IDE, dominant
            raw.bit(false);                          // r0
        }

        let dlc = if remote { data.len() as u32 } else { data.len().min(8) as u32 };
        raw.field(dlc, 4);
        if !remote {
            for b in data.iter().take(8) {
                raw.field(*b as u32, 8);
            }
        }

        // The CRC covers everything so far, destuffed, and is itself stuffed.
        let crc = crc15(&raw.bits);
        raw.field(crc as u32, 15);

        let mut wire_bits = stuff(&raw.bits);
        wire_bits.push(true);                        // CRC delimiter
        wire_bits.push(false);                       // ACK slot: a node answers
        wire_bits.push(true);                        // ACK delimiter
        for _ in 0..7 {
            wire_bits.push(true);                    // end of frame
        }
        for _ in 0..3 {
            wire_bits.push(true);                    // interframe space
        }
        self.emit(&wire_bits);
    }

    /// A frame nobody acknowledges - the ACK slot stays recessive.
    ///
    /// What a bus with one node looks like, and the commonest thing to be
    /// looking for when a CAN link will not come up.
    pub fn frame_unacked(&mut self, id: u32, data: &[u8]) {
        let mut raw = Raw::new();
        raw.bit(false);
        raw.field(id & 0x7FF, 11);
        raw.bit(false);
        raw.bit(false);
        raw.bit(false);
        raw.field(data.len().min(8) as u32, 4);
        for b in data.iter().take(8) {
            raw.field(*b as u32, 8);
        }
        let crc = crc15(&raw.bits);
        raw.field(crc as u32, 15);

        let mut wire_bits = stuff(&raw.bits);
        wire_bits.push(true);                        // CRC delimiter
        wire_bits.push(true);                        // ACK slot left recessive
        wire_bits.push(true);
        for _ in 0..10 {
            wire_bits.push(true);
        }
        self.emit(&wire_bits);
    }

    /// A frame whose CRC is wrong, for testing that the check is real.
    pub fn frame_bad_crc(&mut self, id: u32, data: &[u8]) {
        let mut raw = Raw::new();
        raw.bit(false);
        raw.field(id & 0x7FF, 11);
        raw.bit(false);
        raw.bit(false);
        raw.bit(false);
        raw.field(data.len().min(8) as u32, 4);
        for b in data.iter().take(8) {
            raw.field(*b as u32, 8);
        }
        let crc = crc15(&raw.bits) ^ 0x0001;         // one bit wrong
        raw.field(crc as u32, 15);

        let mut wire_bits = stuff(&raw.bits);
        wire_bits.push(true);
        wire_bits.push(false);
        wire_bits.push(true);
        for _ in 0..10 {
            wire_bits.push(true);
        }
        self.emit(&wire_bits);
    }

    /// An error frame: six dominant bits, which violates the stuffing rule on
    /// purpose and is how a node says it saw something wrong.
    pub fn error_frame(&mut self) {
        let mut bits = vec![false; 6];               // error flag
        bits.extend(std::iter::repeat(true).take(8)); // error delimiter
        self.emit(&bits);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stuffing_breaks_a_run_of_five() {
        let bits = vec![true; 10];
        let stuffed = stuff(&bits);
        // Two stuff bits in ten identical: one after the fifth, one after the
        // next five.
        assert!(stuffed.len() > bits.len());
        // And no run of six survives, which is the whole point.
        let mut run = 1;
        for pair in stuffed.windows(2) {
            run = if pair[0] == pair[1] { run + 1 } else { 1 };
            assert!(run <= 5, "a run of {run} survived stuffing");
        }
    }

    #[test]
    fn stuffing_leaves_alternating_bits_alone() {
        let bits: Vec<bool> = (0..20).map(|i| i % 2 == 0).collect();
        assert_eq!(stuff(&bits), bits);
    }

    /// The CRC has to be a function of the bits and nothing else, or a decoder
    /// recomputing it can never agree.
    #[test]
    fn the_crc_is_deterministic_and_sensitive() {
        let a: Vec<bool> = vec![false, true, true, false, true, false, false, true];
        let mut b = a.clone();
        b[3] = !b[3];
        assert_eq!(crc15(&a), crc15(&a));
        assert_ne!(crc15(&a), crc15(&b), "one flipped bit must change the CRC");
        assert!(crc15(&a) <= 0x7FFF, "the CRC is fifteen bits");
    }

    #[test]
    fn a_frame_produces_edges_and_ends_idle() {
        let mut c = Can::new(500_000);
        c.frame(0x123, false, &[0xDE, 0xAD], false);
        assert!(c.wire.transitions() > 10);
        assert!(c.wire.level(0), "the bus must be left recessive");
    }

    #[test]
    fn generators_are_deterministic() {
        let build = || {
            let mut c = Can::new(500_000);
            c.frame(0x123, false, &[1, 2, 3], false);
            c.wire.chunk(0)
        };
        assert_eq!(build(), build());
    }
}
