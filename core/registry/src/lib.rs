//! Which decoder to use, and how to configure it.
//!
//! The CLI, the golden tests and eventually the GUI all need to answer "what
//! decodes this capture", and the answer should not be written out three times.
//!
//! # Guessing from the channel names
//!
//! A capture records what its channels were called, and those names are a
//! better guide than any heuristic over the waveform: SCL and SDA are a
//! two-wire bus, CLK/MOSI/MISO/CS is SPI, MDC and MDIO is MDIO. It is a guess
//! and it says so - `--protocol` overrides it, and the CLI prints what it chose.
//!
//! The one genuinely ambiguous case is I2C against I3C, which share both wires
//! and most of their framing. The guess is I2C, because it is the commoner
//! traffic and because an I3C capture decoded as I2C is readable but wrong in
//! its labels, where the reverse turns ordinary acknowledges into T-bits.

use decode::BusDecoder;
use schema::Protocol;

/// Everything the CLI can decode, with a word on each for `--help`.
pub const PROTOCOLS: &[(Protocol, &str)] = &[
    (Protocol::I2c, "two wires: START/STOP, addresses, ACK/NACK, repeated start"),
    (Protocol::I3c, "the same two wires: CCCs by name, ENTDAA, IBIs, T-bits"),
    (Protocol::Spi, "four wires: all four modes, CS-bounded transfers"),
    (Protocol::Mdio, "two wires: clause 22 and 45, with turnaround checking"),
    (Protocol::Uart, "one wire: baud measured or given, parity and framing"),
    (Protocol::Can,
     "one wire: 2.0B standard and extended, stuffing, CRC-15, acknowledge"),
];

/// Which channel index a name sits at, if the capture has it.
fn channel(capture: &file::Capture, want: &str) -> Option<u8> {
    capture
        .session
        .channels
        .iter()
        .position(|n| n.eq_ignore_ascii_case(want))
        .map(|i| i as u8)
}

fn has(capture: &file::Capture, names: &[&str]) -> bool {
    names.iter().all(|n| channel(capture, n).is_some())
}

/// What this capture looks like, from its channel names.
pub fn guess(capture: &file::Capture) -> Protocol {
    if has(capture, &["CAN"]) {
        Protocol::Can
    } else if has(capture, &["CLK", "MOSI"]) || has(capture, &["SCK", "MOSI"]) {
        Protocol::Spi
    } else if has(capture, &["MDC", "MDIO"]) {
        Protocol::Mdio
    } else if has(capture, &["SCL", "SDA"]) {
        // Ambiguous with I3C by construction; see the note at the top.
        Protocol::I2c
    } else if capture.session.channels.len() == 1 {
        Protocol::Uart
    } else {
        Protocol::I2c
    }
}

/// Build the decoder for a protocol, wired to this capture's channels.
///
/// Channel lookup falls back to the conventional order when a capture does not
/// name its channels usefully, which a capture from another tool may not.
pub fn decoder(protocol: Protocol, capture: &file::Capture) -> Box<dyn BusDecoder> {
    let at = |name: &str, default: u8| channel(capture, name).unwrap_or(default);

    match protocol {
        Protocol::I2c => Box::new(i2c::Decoder::new(i2c::Config {
            channels: i2c::Channels { scl: at("SCL", 0), sda: at("SDA", 1) },
            ..i2c::Config::default()
        })),
        Protocol::I3c => Box::new(i3c::Decoder::new(i3c::Config {
            channels: i3c::Channels { scl: at("SCL", 0), sda: at("SDA", 1) },
            ..i3c::Config::default()
        })),
        Protocol::Spi => Box::new(spi::Decoder::new(spi::Config {
            channels: spi::Channels {
                clk: channel(capture, "CLK").or(channel(capture, "SCK")).unwrap_or(0),
                mosi: at("MOSI", 1),
                miso: at("MISO", 2),
                cs: at("CS", 3),
            },
            ..spi::Config::default()
        })),
        Protocol::Mdio => Box::new(mdio::Decoder::new(mdio::Config {
            channels: mdio::Channels { mdc: at("MDC", 0), mdio: at("MDIO", 1) },
            ..mdio::Config::default()
        })),
        Protocol::Uart => Box::new(uart::Decoder::new(uart::Config {
            channel: channel(capture, "RX").or(channel(capture, "TX")).unwrap_or(0),
            ..uart::Config::default()
        })),
        Protocol::Can => Box::new(can::Decoder::new(can::Config {
            channel: channel(capture, "CAN").or(channel(capture, "RX")).unwrap_or(0),
            ..can::Config::default()
        })),
    }
}

/// Apply overrides a user typed, where the protocol has them.
pub struct Options {
    pub spi_mode: Option<u8>,
    pub spi_bits: Option<u8>,
    pub uart_baud: Option<u64>,
    /// "n", "e" or "o". A UART capture cannot say which it is - the parity bit
    /// looks like a data bit until you know how many there are - so it has to
    /// be told, and getting it wrong shows as framing errors on every frame.
    pub uart_parity: Option<String>,
    pub mdio_preamble: Option<u8>,
    pub can_bitrate: Option<u64>,
}

impl Options {
    /// Settings named the way a script or a command line names them.
    ///
    /// One vocabulary for the CLI's flags, the golden corpus and the UI, so a
    /// capture configured one way in one of them is configured the same way in
    /// the others.
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let mut out = Options::none();
        for (key, value) in pairs {
            match *key {
                "spi_mode" => out.spi_mode = value.parse().ok(),
                "spi_bits" => out.spi_bits = value.parse().ok(),
                "uart_baud" => out.uart_baud = value.parse().ok(),
                "uart_parity" => out.uart_parity = Some((*value).to_string()),
                "mdio_preamble" => out.mdio_preamble = value.parse().ok(),
                "can_bitrate" => out.can_bitrate = value.parse().ok(),
                _ => {}
            }
        }
        out
    }

    /// No overrides, for callers that only want the defaults.
    pub fn none() -> Self {
        Options { spi_mode: None, spi_bits: None, uart_baud: None,
                  uart_parity: None, mdio_preamble: None, can_bitrate: None }
    }

    pub fn is_empty(&self) -> bool {
        self.spi_mode.is_none() && self.spi_bits.is_none()
            && self.uart_baud.is_none() && self.uart_parity.is_none()
            && self.mdio_preamble.is_none() && self.can_bitrate.is_none()
    }
}

/// A decoder with the caller's overrides applied.
pub fn decoder_with(
    protocol: Protocol,
    capture: &file::Capture,
    options: &Options,
) -> Box<dyn BusDecoder> {
    if options.is_empty() {
        return decoder(protocol, capture);
    }
    let at = |name: &str, default: u8| channel(capture, name).unwrap_or(default);

    match protocol {
        Protocol::Spi => Box::new(spi::Decoder::new(spi::Config {
            channels: spi::Channels {
                clk: channel(capture, "CLK").or(channel(capture, "SCK")).unwrap_or(0),
                mosi: at("MOSI", 1),
                miso: at("MISO", 2),
                cs: at("CS", 3),
            },
            mode: options.spi_mode.unwrap_or(0),
            bits: options.spi_bits.unwrap_or(8),
            ..spi::Config::default()
        })),
        Protocol::Uart => Box::new(uart::Decoder::new(uart::Config {
            channel: channel(capture, "RX").or(channel(capture, "TX")).unwrap_or(0),
            baud: options.uart_baud,
            parity: match options.uart_parity.as_deref() {
                Some("e") | Some("even") => uart::Parity::Even,
                Some("o") | Some("odd") => uart::Parity::Odd,
                _ => uart::Parity::None,
            },
            ..uart::Config::default()
        })),
        Protocol::Mdio => Box::new(mdio::Decoder::new(mdio::Config {
            channels: mdio::Channels { mdc: at("MDC", 0), mdio: at("MDIO", 1) },
            preamble_bits: options.mdio_preamble.unwrap_or(32),
            ..mdio::Config::default()
        })),
        Protocol::Can => Box::new(can::Decoder::new(can::Config {
            channel: channel(capture, "CAN").or(channel(capture, "RX")).unwrap_or(0),
            bitrate: options.can_bitrate,
            ..can::Config::default()
        })),
        other => decoder(other, capture),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture_with(channels: &[&str]) -> file::Capture {
        let chunk = file::SampleChunk {
            id: 0, start: 0, end: 10,
            times: vec![0, 10], lines: vec![0xFF, 0x00],
        };
        file::Capture {
            session: file::Session {
                format_version: file::FORMAT_VERSION,
                schema_version: schema::SCHEMA_VERSION,
                source: "test".into(),
                device_id: String::new(),
                firmware_version: String::new(),
                host_software: String::new(),
                started_utc: String::new(),
                channels: channels.iter().map(|s| s.to_string()).collect(),
                tick_hz: 1_000_000_000_000,
                timing: file::Timing::Measured,
            },
            index: file::rebuild_index(std::slice::from_ref(&chunk), &[],
                                       &schema::Decoded::default()),
            chunks: vec![chunk],
            gaps: vec![],
            decoders: vec![],
            decoded: schema::Decoded::default(),
            annotations: vec![],
            truncated_at: None,
        }
    }

    #[test]
    fn channel_names_pick_the_protocol() {
        assert_eq!(guess(&capture_with(&["SCL", "SDA"])), Protocol::I2c);
        assert_eq!(guess(&capture_with(&["CLK", "MOSI", "MISO", "CS"])), Protocol::Spi);
        assert_eq!(guess(&capture_with(&["SCK", "MOSI", "MISO", "CS"])), Protocol::Spi);
        assert_eq!(guess(&capture_with(&["MDC", "MDIO"])), Protocol::Mdio);
        assert_eq!(guess(&capture_with(&["RX"])), Protocol::Uart);
    }

    #[test]
    fn a_decoder_is_wired_to_the_channels_the_capture_names() {
        // Channels in an unusual order: the decoder must follow the names, not
        // the positions, or a capture from another tool decodes to nonsense.
        let cap = capture_with(&["SDA", "SCL"]);
        let info = decoder(Protocol::I2c, &cap).info();
        let setting = |k: &str| info.settings.iter()
            .find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(setting("sda_channel"), "0");
        assert_eq!(setting("scl_channel"), "1");
    }

    #[test]
    fn overrides_reach_the_decoder() {
        let cap = capture_with(&["CLK", "MOSI", "MISO", "CS"]);
        let options = Options { spi_mode: Some(3), spi_bits: Some(16),
                                ..Options::none() };
        let info = decoder_with(Protocol::Spi, &cap, &options).info();
        let setting = |k: &str| info.settings.iter()
            .find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(setting("mode"), "3");
        assert_eq!(setting("bits"), "16");
    }

    #[test]
    fn every_protocol_in_the_list_builds_a_decoder() {
        let cap = capture_with(&["SCL", "SDA"]);
        for (p, _) in PROTOCOLS {
            let info = decoder(*p, &cap).info();
            assert_eq!(info.protocol, *p, "{p:?} built the wrong decoder");
            assert!(!info.version.is_empty());
        }
    }
}
