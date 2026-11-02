//! Reading raw edges off a BUSBRIDGE board into capture chunks.
//!
//! # What the hardware gives, and what it does not
//!
//! The board's `SNIFF:RAW:*` mode timestamps every SCL and SDA edge into a RAM
//! ring at 250 MHz and hands the ring over afterwards. It is a burst: 8192
//! edges, a couple of milliseconds of a busy bus. USB full speed cannot carry a
//! 400 kHz bus continuously and nothing here pretends otherwise - when the ring
//! fills, capture stops and the board says so, and that becomes a gap record.
//!
//! So this is not the streaming acquisition service section 4.1 describes. It
//! is the same shape - sequence checking, explicit gaps, chunks written before
//! decoding - against hardware that captures in bursts. The seam is the capture
//! file: everything above it cannot tell the difference, which is the point of
//! having the file format be the contract.
//!
//! # Timestamps
//!
//! The board counts ticks in a 32-bit counter at a rate it reports, and that
//! counter wraps every 17 seconds at 250 MHz. Unwrapped here, once, on the way
//! in - a wrap that reaches the file would show as the capture jumping
//! backwards, and every consumer would need to know about it.
//!
//! # Why the C library
//!
//! Talking WinUSB from here would be a second implementation of the transport
//! the BUSBRIDGE C library already has, tested against the same boards. The
//! GUI links it the same way, statically, so there is no DLL to find at run
//! time.

// The one crate in the workspace that cannot forbid unsafe: it is the FFI
// boundary. Denied everywhere instead, with a single allowed module holding
// every call, so "where is the unsafe" has a one-word answer.
#![deny(unsafe_code)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use file::{Gap, SampleChunk, Session};
use schema::Picos;

mod ffi {
    use super::*;

    pub type Handle = *mut c_void;
    pub type Device = *mut c_void;

    extern "C" {
        pub fn bb_find_devices(first: Device) -> Device;
        pub fn bb_device_port(dev: Device) -> *const c_char;
        pub fn bb_device_serial(dev: Device) -> *const c_char;
        pub fn bb_open(dev: Device) -> Handle;
        pub fn bb_close(hndl: Handle) -> c_int;
        pub fn bb_set_timeout(hndl: Handle, ms: c_int) -> c_int;
        pub fn bb_command(
            hndl: Handle, cmd: *const c_char, reply: *mut c_char, sz: c_int) -> c_int;
        pub fn bb_strerror(code: c_int) -> *const c_char;
        pub fn bb_last_error_code() -> c_int;
        pub fn bb_last_reply() -> *const c_char;
        pub fn bb_get_serial_number(hndl: Handle, buf: *mut c_char, sz: c_int) -> c_int;
        pub fn bb_get_version(hndl: Handle, buf: *mut c_char, sz: c_int) -> c_int;
    }
}

#[derive(Debug)]
pub struct Error(pub String);

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;

/// Every call into the C library, and nothing else.
///
/// Each raw pointer here came from that library and is handed straight back to
/// it; none is constructed, arithmetic'd or outlived. Keeping them in one
/// module means the answer to "what can go wrong at the boundary" is this file
/// and not a search.
#[allow(unsafe_code)]
mod unsafe_calls {
    use super::*;

    pub fn find_first() -> Option<ffi::Device> {
        let dev = unsafe { ffi::bb_find_devices(std::ptr::null_mut()) };
        (!dev.is_null()).then_some(dev)
    }

    pub fn next(dev: ffi::Device) -> Option<ffi::Device> {
        let dev = unsafe { ffi::bb_find_devices(dev) };
        (!dev.is_null()).then_some(dev)
    }

    pub fn port_of(dev: ffi::Device) -> String {
        let p = unsafe { ffi::bb_device_port(dev) };
        if p.is_null() {
            return String::new();
        }
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    /// The board's serial, which is what tells two of them apart.
    ///
    /// Every USB board reports the same port string - "USB" - so on a bench
    /// with two attached, matching on port alone can only ever say "several
    /// boards attached" and refuse. The serial is available before opening,
    /// which is what makes it usable for choosing *which* to open.
    pub fn serial_of(dev: ffi::Device) -> String {
        let p = unsafe { ffi::bb_device_serial(dev) };
        if p.is_null() {
            return String::new();
        }
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    pub fn open(dev: ffi::Device) -> Option<ffi::Handle> {
        let h = unsafe { ffi::bb_open(dev) };
        (!h.is_null()).then_some(h)
    }

    pub fn close(h: ffi::Handle) {
        unsafe { ffi::bb_close(h) };
    }

    pub fn set_timeout(h: ffi::Handle, ms: i32) {
        unsafe { ffi::bb_set_timeout(h, ms) };
    }

    pub fn command(h: ffi::Handle, cmd: &str) -> Result<String> {
        let c = CString::new(cmd).map_err(|_| Error("command contains a NUL".into()))?;
        let mut buf = vec![0i8; 1400];
        let rc = unsafe {
            ffi::bb_command(h, c.as_ptr(), buf.as_mut_ptr(), buf.len() as c_int)
        };
        if rc != 0 {
            let text = unsafe { CStr::from_ptr(ffi::bb_strerror(rc)) }
                .to_string_lossy().into_owned();
            let reply = unsafe { ffi::bb_last_reply() };
            let detail = if reply.is_null() {
                String::new()
            } else {
                unsafe { CStr::from_ptr(reply) }.to_string_lossy().into_owned()
            };
            let code = unsafe { ffi::bb_last_error_code() };
            return Err(Error(format!("{cmd}: {text}{}",
                if detail.is_empty() { String::new() }
                else { format!(" (firmware {code}: {detail})") })));
        }
        Ok(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned())
    }

    pub fn text(h: ffi::Handle, which: u8) -> String {
        let mut buf = vec![0i8; 128];
        let rc = unsafe {
            match which {
                0 => ffi::bb_get_serial_number(h, buf.as_mut_ptr(), buf.len() as c_int),
                _ => ffi::bb_get_version(h, buf.as_mut_ptr(), buf.len() as c_int),
            }
        };
        if rc != 0 {
            return String::new();
        }
        unsafe { CStr::from_ptr(buf.as_ptr()) }.to_string_lossy().into_owned()
    }
}

/// An open board.
pub struct Board {
    handle: ffi::Handle,
    pub port: String,
    pub serial: String,
    pub firmware: String,
}

impl Drop for Board {
    fn drop(&mut self) {
        unsafe_calls::close(self.handle);
    }
}

/// Every board attached.
pub fn list() -> Vec<String> {
    let mut out = Vec::new();
    let mut dev = unsafe_calls::find_first();
    while let Some(d) = dev {
        out.push(unsafe_calls::port_of(d));
        dev = unsafe_calls::next(d);
    }
    out
}

impl Board {
    /// Open a board by port, or the only one attached when `port` is None.
    pub fn open(port: Option<&str>) -> Result<Self> {
        let mut dev = unsafe_calls::find_first();
        let mut found = None;
        let mut seen = Vec::new();
        while let Some(d) = dev {
            let p = unsafe_calls::port_of(d);
            let ser = unsafe_calls::serial_of(d);
            // Listed as "port (serial)" so the refusal below names something a
            // caller can actually pass back.
            seen.push(if ser.is_empty() { p.clone() } else { format!("{p} ({ser})") });
            let want_l = port.map(|w| w.to_lowercase());
            let matches = match (&want_l, port) {
                (None, _) => true,
                (Some(w), _) => {
                    p.eq_ignore_ascii_case(w)
                        || p.to_lowercase().contains(w.as_str())
                        || ser.to_lowercase() == *w
                        || ser.to_lowercase().starts_with(w.as_str())
                }
            };
            if matches && found.is_none() {
                found = Some(d);
            }
            dev = unsafe_calls::next(d);
        }

        let dev = found.ok_or_else(|| Error(match port {
            Some(want) => format!("no board matching {want:?}. Attached: {}",
                                  if seen.is_empty() { "none".into() }
                                  else { seen.join(", ") }),
            None => "no board found. Its own USB connector needs a cable to this \
                     machine; the ST-LINK cable carries debug only.".into(),
        }))?;

        // Refuse to guess between two boards: capturing from the wrong one is a
        // confusing thing to discover after the fact, and the same reason
        // scripts/flash.ps1 refuses.
        // Only ambiguous when nothing was asked for. A serial that named one
        // board has already chosen it above.
        if port.is_none() && seen.len() > 1 {
            return Err(Error(format!(
                "several boards attached, so name one with --port: {}",
                seen.join(", "))));
        }

        let handle = unsafe_calls::open(dev)
            .ok_or_else(|| Error("the board is attached but would not open. \
                                  Another program may be holding it - one process \
                                  at a time.".into()))?;
        unsafe_calls::set_timeout(handle, 5000);

        Ok(Board {
            port: unsafe_calls::port_of(dev),
            serial: unsafe_calls::text(handle, 0),
            firmware: unsafe_calls::text(handle, 1),
            handle,
        })
    }

    pub fn command(&self, cmd: &str) -> Result<String> {
        unsafe_calls::command(self.handle, cmd)
    }
}

/// Key=value fields out of a reply line.
fn fields(reply: &str) -> std::collections::HashMap<&str, &str> {
    reply
        .split_whitespace()
        .filter_map(|t| t.split_once('='))
        .collect()
}

fn number(map: &std::collections::HashMap<&str, &str>, key: &str) -> u64 {
    map.get(key).and_then(|v| v.parse().ok()).unwrap_or(0)
}

/// What one burst produced.
pub struct Burst {
    pub chunk: SampleChunk,
    pub gaps: Vec<Gap>,
    pub session: Session,
    /// True when the board's ring filled - the capture ends there because it
    /// ran out of room, not because the bus went quiet.
    pub full: bool,
}

/// Arm the board, wait, and read the edges back.
///
/// `settle_ms` is how long to let the bus be watched before draining. A capture
/// is a burst, so this is the whole of it.
pub fn burst(
    board: &Board,
    max_edges: u32,
    settle_ms: u64,
    self_test: bool,
) -> Result<Burst> {
    let armed = if self_test {
        // Drives a known pattern on the taps and captures it. With nothing
        // wired this is the only way to get real edges out of real hardware,
        // and it exercises the whole path - pins, both EXTI edges, timestamps,
        // ring, transport.
        board.command("SNIFF:RAW:TEST")?
    } else {
        board.command(&format!("SNIFF:RAW:START {max_edges}"))?
    };
    let armed = fields(&armed);
    let tick_hz = {
        let hz = number(&armed, "tick_hz");
        if hz == 0 { 250_000_000 } else { hz }
    };

    if !self_test {
        std::thread::sleep(std::time::Duration::from_millis(settle_ms));
        board.command("SNIFF:RAW:STOP")?;
    }

    let stat = board.command("SNIFF:RAW:STAT?")?;
    let stat = fields(&stat);
    let count = number(&stat, "edges") as usize;
    let full = stat.get("full").map(|v| *v == "1").unwrap_or(false);

    // Drain. Each record is five bytes: little-endian tick, then the line mask.
    let mut ticks: Vec<u32> = Vec::with_capacity(count);
    let mut lines: Vec<u8> = Vec::with_capacity(count);
    while ticks.len() < count {
        let reply = board.command("SNIFF:RAW:READ? 51")?;
        let bytes = parse_hex(&reply);
        if bytes.is_empty() {
            // The board says there is nothing more even though it counted more.
            // Reported as a gap rather than silently returning short - that is
            // the whole rule about loss being explicit.
            break;
        }
        for rec in bytes.chunks_exact(5) {
            ticks.push(u32::from_le_bytes([rec[0], rec[1], rec[2], rec[3]]));
            lines.push(rec[4]);
        }
    }

    let short = ticks.len() < count;

    // Unwrap the 32-bit counter and convert to picoseconds relative to the
    // first edge. Done once, here, so nothing downstream has to know the
    // counter is 32 bits or what rate it ran at.
    let ps_per_tick = 1_000_000_000_000u128 / tick_hz as u128;
    let mut times: Vec<Picos> = Vec::with_capacity(ticks.len());
    let mut wraps: u64 = 0;
    for (i, &t) in ticks.iter().enumerate() {
        if i > 0 && t < ticks[i - 1] {
            wraps += 1;
        }
        let absolute = (wraps as u128) * (1u128 << 32) + t as u128;
        times.push((absolute * ps_per_tick) as u64);
    }
    if let Some(&first) = times.first() {
        for t in &mut times {
            *t -= first;
        }
    }

    let start = *times.first().unwrap_or(&0);
    let end = *times.last().unwrap_or(&0);

    let mut gaps = Vec::new();
    if full {
        gaps.push(Gap {
            start: end,
            end,
            reason: "the board's edge buffer filled and capture stopped".into(),
            lost: None,
        });
    }
    if short {
        gaps.push(Gap {
            start: end,
            end,
            reason: format!(
                "the board reported {count} edges and delivered {}", ticks.len()),
            lost: Some((count - ticks.len()) as u64),
        });
    }

    let session = Session {
        format_version: file::FORMAT_VERSION,
        schema_version: schema::SCHEMA_VERSION,
        source: format!("busbridge:{}", board.port),
        device_id: board.serial.clone(),
        firmware_version: board.firmware.clone(),
        host_software: concat!("sniffer ", env!("CARGO_PKG_VERSION")).into(),
        started_utc: now_utc(),
        channels: vec!["SCL".into(), "SDA".into()],
        tick_hz,
        // Edges counted by the board against its own clock.
        timing: file::Timing::Measured,
    };

    Ok(Burst {
        chunk: SampleChunk { id: 0, start, end, times, lines },
        gaps,
        session,
        full,
    })
}

/// Hex bytes out of an `OK` payload, which the firmware sends space separated.
fn parse_hex(reply: &str) -> Vec<u8> {
    reply
        .split_whitespace()
        .filter_map(|t| u8::from_str_radix(t, 16).ok())
        .collect()
}

/// A UTC stamp for the session header, which nothing computes with.
///
/// Hand-rolled rather than pulling in a date library for one string: this is
/// the only place in the workspace that needs the wall clock, and a dependency
/// that exists to format one field is a dependency to keep updated for ever.
fn now_utc() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
            rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// Days since the epoch to a calendar date. Howard Hinnant's civil_from_days,
/// which is the standard way to do this without a library.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_payloads_parse() {
        assert_eq!(parse_hex("DE AD BE EF"), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(parse_hex(""), Vec::<u8>::new());
        // "empty remaining=0 full=0" is what the board says when drained; none
        // of those tokens is a hex byte pair, so nothing is invented from it.
        assert_eq!(parse_hex("empty remaining=0 full=0"), Vec::<u8>::new());
    }

    #[test]
    fn key_value_replies_parse() {
        let f = fields("raw=1 max=8192 tick_hz=250000000 SCL=PC2 SDA=PC3");
        assert_eq!(f.get("max"), Some(&"8192"));
        assert_eq!(number(&f, "tick_hz"), 250_000_000);
        assert_eq!(number(&f, "absent"), 0);
    }

    #[test]
    fn the_date_helper_agrees_with_known_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // The leap day, which is where a hand-rolled calendar goes wrong.
        // 19723 is 1 January, and 31 + 28 days later is the 29th.
        assert_eq!(civil_from_days(19_723 + 59), (2024, 2, 29));
        assert_eq!(civil_from_days(19_723 + 60), (2024, 3, 1));
        // And a non-leap year does not have one: 2024 is 366 days long, so the
        // same offset into 2025 lands on 1 March rather than 29 February.
        const JAN1_2025: i64 = 19_723 + 366;
        assert_eq!(civil_from_days(JAN1_2025), (2025, 1, 1));
        assert_eq!(civil_from_days(JAN1_2025 + 59), (2025, 3, 1));
    }
}
