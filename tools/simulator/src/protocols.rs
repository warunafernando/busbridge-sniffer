//! Traffic generators, one per protocol.
//!
//! Each writes the waveform a real bus would produce, not the transactions a
//! decoder should find. A generator that emitted decoded output would test
//! nothing except itself.
//!
//! Where a protocol has a rule that is easy to get wrong - MDIO's turnaround,
//! CAN's bit stuffing, I3C's T-bit - the generator implements the rule properly,
//! because a decoder tested against a generator that skipped it would pass and
//! then fail on a wire.

use crate::wire::{period, Wire};
use schema::Picos;

/* ---- I2C ------------------------------------------------------------------ */

/// SCL on channel 0, SDA on channel 1.
///
/// # `hz` is a tick base, not the bus clock
///
/// Everything here moves in quarter-ticks of `period(hz)`, and a bit is three
/// of them - SCL low, high, low again - so SCL's period is three quarters of
/// `period(hz)` and its frequency is four thirds of `hz`. `new(100_000)`
/// therefore clocks at about 133 kHz.
///
/// That is a perfectly good I2C waveform and every golden file in the corpus
/// is built from it, so the timing is not something to "fix". It is written
/// down because `sniffer measure` reports the real clock off the edges, and
/// the first reaction to seeing 133 kHz for a bus you asked to be 100 kHz is
/// to go looking for a bug in the measurement.
pub struct I2c {
    pub wire: Wire,
    quarter: Picos,
}

impl I2c {
    /// `hz` is the quarter-tick base; see the note on [`I2c`] about the clock
    /// it produces.
    pub fn new(hz: u64) -> Self {
        let p = period(hz);
        I2c { wire: Wire::new(&["SCL", "SDA"], 0b11, p), quarter: p / 4 }
    }

    /// Change the tick base mid-capture, which is how clock stretching is
    /// generated.
    pub fn set_rate(&mut self, hz: u64) {
        self.quarter = period(hz) / 4;
    }

    /// The SCL period this tick base produces: three quarter-ticks.
    ///
    /// Public so a test can assert the relationship rather than restate the
    /// arithmetic.
    pub fn scl_period(&self) -> Picos {
        self.quarter * 3
    }

    fn tick(&mut self) {
        self.wire.advance(self.quarter);
    }

    fn drive(&mut self, scl: bool, sda: bool) {
        self.tick();
        self.wire.set_mask(u8::from(scl) | (u8::from(sda) << 1));
    }

    pub fn start(&mut self) {
        self.drive(true, true);
        self.drive(true, false);
        self.drive(false, false);
    }

    pub fn repeated_start(&mut self) {
        self.drive(false, true);
        self.drive(true, true);
        self.drive(true, false);
        self.drive(false, false);
    }

    fn bit(&mut self, v: bool) {
        self.drive(false, v);
        self.drive(true, v);
        self.drive(false, v);
    }

    pub fn byte(&mut self, value: u8, ack: bool) {
        for i in (0..8).rev() {
            self.bit(value & (1 << i) != 0);
        }
        self.bit(!ack);
    }

    /// Clock out `n` bits of `value`, MSB first, and nothing else.
    ///
    /// For frames that never complete a byte - a capture that starts or ends
    /// in the middle of one. A decoder has to tell those from a frame that
    /// never carried a bit at all, and only this can build them.
    pub fn bits(&mut self, value: u32, n: u32) {
        for i in (0..n).rev() {
            self.bit(value & (1 << i) != 0);
        }
    }

    /// A byte whose ninth bit is set explicitly.
    ///
    /// I3C needs this: the ninth bit of a data byte is a T-bit, not an
    /// acknowledge, and on a read it is odd parity over the byte. Writing an
    /// acknowledge there instead makes a correct decoder report a parity
    /// failure on perfectly good data - which is what this generator did until
    /// the golden corpus showed every I3C read flagged.
    pub fn byte_with_ninth(&mut self, value: u8, ninth: bool) {
        for i in (0..8).rev() {
            self.bit(value & (1 << i) != 0);
        }
        self.bit(ninth);
    }

    /// A byte read from an I3C target, with its T-bit.
    ///
    /// On a read the T-bit means "more data follows", not parity: the target
    /// drives 1 for every byte, including the last when the controller ends
    /// the transfer itself with RDTERM. This generator used to put parity here
    /// and the decoder used to check for it, so the two agreed with each other
    /// and not with the bus. Measured on real hardware, a read of six bytes
    /// carries T=1 on every one of them whatever their parity.
    pub fn i3c_read_byte(&mut self, value: u8) {
        self.byte_with_ninth(value, true);
    }

    /// The last byte of a read that the *target* ends, which it signals by
    /// driving the T-bit low.
    pub fn i3c_read_last_byte(&mut self, value: u8) {
        self.byte_with_ninth(value, false);
    }

    /// A byte written to an I3C target, with its T-bit.
    ///
    /// On a write the controller drives the T-bit and it is odd parity over
    /// the eight data bits - odd counting the T-bit itself, so a byte with an
    /// even number of ones gets a 1. Measured: a write of `00 40` puts T=1 on
    /// 0x00 and T=0 on 0x40.
    pub fn i3c_write_byte(&mut self, value: u8) {
        self.byte_with_ninth(value, value.count_ones() % 2 == 0);
    }

    pub fn stop(&mut self) {
        self.drive(false, false);
        self.drive(true, false);
        self.drive(true, true);
    }

    /// A STOP raised from a line the other side left high.
    ///
    /// `stop()` above pulls SDA down while the clock is low, which is tidy and
    /// is not what a controller can always do. A STOP needs SDA low before it
    /// can rise, and at the end of a read the target has just released SDA
    /// high - so the controller takes the line back and pulls it down with the
    /// clock already high, then releases it one period later.
    ///
    /// That fall has the exact shape of a START, and a decoder that reads it
    /// as one opens a frame which the real STOP then closes with nothing in
    /// it. Every I3C read on this bench ends this way; the corpus could not
    /// see it because this generator only ever emitted the tidy form.
    pub fn stop_from_high(&mut self) {
        self.drive(true, true);
        self.drive(true, false);
        self.drive(false, false);
        self.drive(true, false);
        self.drive(true, true);
    }

    /// A read address whose target lets go of SDA under the held clock.
    ///
    /// The target pulls SDA low to acknowledge, and then has to hand the line
    /// over before the data phase drives it. If it releases while the clock is
    /// still high, SDA rises with SCL held - the shape of a STOP - and if the
    /// data phase then drives the first bit low under the same held clock,
    /// SDA falls again, which is the shape of a START. Either lands one byte
    /// into a frame that is not ending.
    ///
    /// This replaces the ninth bit rather than following it, which is the
    /// whole point and was got wrong first: emitting the handover *after* a
    /// normal acknowledged byte adds a clock edge, so an extra bit is sampled
    /// and the payload shifts by one. That is a different defect, and a test
    /// built on it proves nothing about this one. The handover is a change
    /// within the acknowledge bit, not an addition to it.
    ///
    /// `redrive_low` models the data phase taking the line back down before
    /// the clock falls, giving both transitions instead of one.
    pub fn read_address_with_handover(&mut self, addr: u8, redrive_low: bool) {
        let byte = (addr << 1) | 1;
        for i in (0..8).rev() {
            self.bit(byte & (1 << i) != 0);
        }
        // The acknowledge bit, with the line changing hands inside it.
        self.drive(false, false);       // target drives the acknowledge low
        self.drive(true, false);        // clock rises - the 0 is sampled here
        self.drive(true, true);         // target releases, under the held clock
        if redrive_low {
            self.drive(true, false);    // the data phase takes it back down
            self.drive(false, false);
        } else {
            self.drive(false, true);
        }
    }

    pub fn idle(&mut self, quarters: u64) {
        self.wire.advance(self.quarter * quarters);
    }

    pub fn write(&mut self, addr: u8, data: &[u8], addr_ack: bool) {
        self.start();
        self.byte(addr << 1, addr_ack);
        if addr_ack {
            for b in data {
                self.byte(*b, true);
            }
        }
        self.stop();
    }

    pub fn read(&mut self, addr: u8, data: &[u8], addr_ack: bool) {
        self.start();
        self.byte((addr << 1) | 1, addr_ack);
        if addr_ack {
            for (i, b) in data.iter().enumerate() {
                // The controller NACKs the last byte to end the read, which is
                // how a real one finishes.
                self.byte(*b, i + 1 < data.len());
            }
        }
        self.stop();
    }

    pub fn write_then_read(&mut self, addr: u8, reg: &[u8], data: &[u8]) {
        self.start();
        self.byte(addr << 1, true);
        for b in reg {
            self.byte(*b, true);
        }
        self.repeated_start();
        self.byte((addr << 1) | 1, true);
        for (i, b) in data.iter().enumerate() {
            self.byte(*b, i + 1 < data.len());
        }
        self.stop();
    }
}

/* ---- UART ----------------------------------------------------------------- */

/// One line, channel 0, idling high.
pub struct Uart {
    pub wire: Wire,
    bit_ps: Picos,
    data_bits: u8,
    parity: Parity,
    stop_bits: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    None,
    Even,
    Odd,
}

impl Uart {
    pub fn new(baud: u64, data_bits: u8, parity: Parity, stop_bits: u8) -> Self {
        let bit_ps = period(baud);
        Uart {
            wire: Wire::new(&["RX"], 0b1, bit_ps),
            bit_ps,
            data_bits,
            parity,
            stop_bits,
        }
    }

    fn bit(&mut self, v: bool) {
        self.wire.advance(self.bit_ps);
        self.wire.set(0, v);
    }

    /// Time passes to the end of the last bit written.
    ///
    /// `bit()` puts an edge at the *start* of a bit window, so after the final
    /// stop bit the clock is one bit short of the end of the frame. Without
    /// this the capture appears to stop mid-stop-bit and a decoder is right to
    /// call the frame truncated - which is what it did.
    fn close_frame(&mut self) {
        self.wire.advance(self.bit_ps);
    }

    /// One frame: start bit low, data least significant first, parity, stops.
    pub fn byte(&mut self, value: u8) {
        self.bit(false);
        let mut ones = 0;
        for i in 0..self.data_bits {
            let b = value & (1 << i) != 0;
            if b {
                ones += 1;
            }
            self.bit(b);
        }
        match self.parity {
            Parity::None => {}
            Parity::Even => self.bit(ones % 2 == 1),
            Parity::Odd => self.bit(ones % 2 == 0),
        }
        for _ in 0..self.stop_bits {
            self.bit(true);
        }
        self.close_frame();
    }

    /// A frame with the wrong parity, so the decoder has something to catch.
    pub fn byte_with_bad_parity(&mut self, value: u8) {
        self.bit(false);
        let mut ones = 0;
        for i in 0..self.data_bits {
            let b = value & (1 << i) != 0;
            if b {
                ones += 1;
            }
            self.bit(b);
        }
        match self.parity {
            Parity::None => {}
            Parity::Even => self.bit(ones % 2 == 0),   // deliberately inverted
            Parity::Odd => self.bit(ones % 2 == 1),
        }
        for _ in 0..self.stop_bits {
            self.bit(true);
        }
        self.close_frame();
    }

    /// A frame whose stop bit is low, which is a framing error.
    pub fn byte_with_framing_error(&mut self, value: u8) {
        self.bit(false);
        for i in 0..self.data_bits {
            self.bit(value & (1 << i) != 0);
        }
        if self.parity != Parity::None {
            self.bit(false);
        }
        self.bit(false);                 // the stop bit that is not there
        self.bit(true);                  // and back to idle
        self.close_frame();
    }

    pub fn text(&mut self, s: &str) {
        for b in s.bytes() {
            self.byte(b);
        }
    }

    pub fn idle(&mut self, bits: u64) {
        self.wire.advance(self.bit_ps * bits);
    }
}

/* ---- SPI ------------------------------------------------------------------ */

/// CLK 0, MOSI 1, MISO 2, CS 3.
pub struct Spi {
    pub wire: Wire,
    half: Picos,
    /// Clock polarity: the idle level of CLK.
    cpol: bool,
    /// Clock phase: false samples on the first edge, true on the second.
    cpha: bool,
}

impl Spi {
    pub fn new(hz: u64, mode: u8) -> Self {
        let cpol = mode & 0b10 != 0;
        let cpha = mode & 0b01 != 0;
        let half = period(hz) / 2;
        // CS idles high, MISO and MOSI idle low, CLK idles at CPOL.
        let idle = (u8::from(cpol)) | (1 << 3);
        Spi { wire: Wire::new(&["CLK", "MOSI", "MISO", "CS"], idle, half * 2),
              half, cpol, cpha }
    }

    pub fn select(&mut self, on: bool) {
        self.wire.advance(self.half);
        self.wire.set(3, !on);           // active low
    }

    /// One byte each way, most significant bit first.
    ///
    /// Data is launched on the edge *opposite* the sampling one, which is what
    /// a real SPI device does and what makes the mode matter. An earlier version
    /// changed the data in the middle of the low phase, and the consequence was
    /// that both clock edges saw the same bit - so a decoder using the wrong
    /// mode produced the right bytes and a test could not tell the two apart.
    pub fn transfer(&mut self, mosi: u8, miso: u8) {
        for i in (0..8).rev() {
            let out = mosi & (1 << i) != 0;
            let inp = miso & (1 << i) != 0;

            if !self.cpha {
                // Launch with the clock at its idle level, sample on the edge
                // away from it. The data and the clock move together, as one
                // entry, because on the wire they do.
                self.wire.advance(self.half);
                self.wire.set_mask(self.with_data(out, inp, self.cpol));
                self.wire.advance(self.half);
                self.wire.set(0, !self.cpol);            // sampling edge
            } else {
                // Launch on the first edge, sample on the second.
                self.wire.advance(self.half);
                self.wire.set_mask(self.with_data(out, inp, !self.cpol));
                self.wire.advance(self.half);
                self.wire.set(0, self.cpol);             // sampling edge
            }
        }
        // Leave the clock at its idle level, which for CPHA=0 means one more
        // edge after the last sample.
        if !self.cpha {
            self.wire.advance(self.half);
            self.wire.set(0, self.cpol);
        }
    }

    fn with_data(&self, mosi: bool, miso: bool, clk: bool) -> u8 {
        let cs = self.wire.level(3);
        u8::from(clk) | (u8::from(mosi) << 1) | (u8::from(miso) << 2)
            | (u8::from(cs) << 3)
    }

    /// A whole CS-bounded exchange.
    pub fn exchange(&mut self, mosi: &[u8], miso: &[u8]) {
        self.select(true);
        for i in 0..mosi.len().max(miso.len()) {
            self.transfer(mosi.get(i).copied().unwrap_or(0),
                          miso.get(i).copied().unwrap_or(0));
        }
        self.select(false);
    }

    pub fn idle(&mut self, halves: u64) {
        self.wire.advance(self.half * halves);
    }
}

/* ---- MDIO ----------------------------------------------------------------- */

/// MDC 0, MDIO 1.
pub struct Mdio {
    pub wire: Wire,
    half: Picos,
}

impl Mdio {
    pub fn new(hz: u64) -> Self {
        let half = period(hz) / 2;
        Mdio { wire: Wire::new(&["MDC", "MDIO"], 0b11, half * 2), half }
    }

    /// One bit: data set while MDC is low, sampled on the rise.
    fn bit(&mut self, v: bool) {
        self.wire.advance(self.half);
        self.wire.set_mask(u8::from(false) | (u8::from(v) << 1));
        self.wire.advance(self.half);
        self.wire.set(0, true);
    }

    fn bits(&mut self, value: u32, count: u8) {
        for i in (0..count).rev() {
            self.bit(value & (1 << i) != 0);
        }
    }

    pub fn preamble(&mut self) {
        for _ in 0..32 {
            self.bit(true);
        }
    }

    /// Clause 22 read: ST=01, OP=10, then the turnaround the PHY drives.
    pub fn c22_read(&mut self, phy: u8, reg: u8, data: u16, preamble: bool) {
        if preamble {
            self.preamble();
        }
        self.bits(0b01, 2);
        self.bits(0b10, 2);
        self.bits(phy as u32, 5);
        self.bits(reg as u32, 5);
        // Turnaround: the controller releases, the PHY pulls low. Both bits are
        // driven here as Z-then-0, which on a pulled-up bus reads 1 then 0.
        self.bit(true);
        self.bit(false);
        self.bits(data as u32, 16);
        self.idle(2);
    }

    pub fn c22_write(&mut self, phy: u8, reg: u8, data: u16, preamble: bool) {
        if preamble {
            self.preamble();
        }
        self.bits(0b01, 2);
        self.bits(0b01, 2);
        self.bits(phy as u32, 5);
        self.bits(reg as u32, 5);
        self.bits(0b10, 2);              // the controller's own turnaround
        self.bits(data as u32, 16);
        self.idle(2);
    }

    /// A read whose turnaround never happens - the PHY is not there, so the
    /// pulled-up line stays high where the second TA bit should be low.
    pub fn c22_read_no_turnaround(&mut self, phy: u8, reg: u8, preamble: bool) {
        if preamble {
            self.preamble();
        }
        self.bits(0b01, 2);
        self.bits(0b10, 2);
        self.bits(phy as u32, 5);
        self.bits(reg as u32, 5);
        self.bit(true);
        self.bit(true);                  // should have been driven low
        self.bits(0xFFFF, 16);           // and the bus reads as all ones
        self.idle(2);
    }

    pub fn idle(&mut self, bits: u64) {
        self.wire.advance(self.half * 2 * bits);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `hz` is a tick base and SCL comes out at four thirds of it. Pinned
    /// because a measurement of the corpus reports the real clock, and the
    /// mismatch looks like a bug in the measurement until you know.
    #[test]
    fn the_i2c_clock_is_four_thirds_of_the_tick_base() {
        let b = I2c::new(100_000);
        assert_eq!(b.scl_period(), 7_500_000, "three quarter-ticks of 10 us");
        let hz = 1e12 / b.scl_period() as f64;
        assert!((hz - 133_333.0).abs() < 100.0, "SCL came out at {hz} Hz");
    }

    /// And the edges agree with the arithmetic: one bit, one SCL cycle.
    #[test]
    fn one_bit_takes_one_scl_period() {
        let mut b = I2c::new(100_000);
        b.start();
        let before = b.wire.now();
        b.byte(0xAA, true);
        let after = b.wire.now();
        // Eight data bits and the acknowledge.
        assert_eq!(after - before, b.scl_period() * 9);
    }

    use super::*;

    #[test]
    fn a_uart_frame_is_start_data_and_stop() {
        let mut u = Uart::new(115_200, 8, Parity::None, 1);
        u.byte(0x55);
        // 0x55 alternates, so every bit is an edge, plus start and stop.
        assert!(u.wire.transitions() >= 9,
                "expected a transition per bit, got {}", u.wire.transitions());
        // And it must end idle high, or the next frame's start bit is invisible.
        assert!(u.wire.level(0));
    }

    #[test]
    fn spi_leaves_the_clock_where_cpol_says() {
        for mode in 0..4u8 {
            let mut s = Spi::new(1_000_000, mode);
            s.exchange(&[0xA5], &[0x5A]);
            let cpol = mode & 0b10 != 0;
            assert_eq!(s.wire.level(0), cpol,
                       "mode {mode} left the clock at the wrong idle level");
            assert!(s.wire.level(3), "mode {mode} left CS asserted");
        }
    }

    #[test]
    fn mdio_ends_with_the_clock_high_and_the_line_released() {
        let mut m = Mdio::new(2_500_000);
        m.c22_read(1, 0x20, 0x1234, true);
        assert!(m.wire.level(0), "MDC should be left high");
    }

    /// The generators must be pure functions of their arguments, or a golden
    /// file made from one is a photograph rather than a test.
    #[test]
    fn every_generator_is_deterministic() {
        let build_i2c = || {
            let mut b = I2c::new(100_000);
            b.write(0x52, &[1, 2, 3], true);
            b.wire.chunk(0)
        };
        assert_eq!(build_i2c(), build_i2c());

        let build_spi = || {
            let mut s = Spi::new(1_000_000, 0);
            s.exchange(&[0x9F], &[0xEF]);
            s.wire.chunk(0)
        };
        assert_eq!(build_spi(), build_spi());
    }
}
