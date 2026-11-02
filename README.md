# Multi-protocol sniffer

Built to `Sniffer_Software_Development_Specification.docx` v1.0. This is
**Phases 0 to 3, and Appendix D**: the contracts, the test infrastructure, the
first end-to-end demo, and all six protocols. What that
covers and what it does not is set out below, because the specification
describes an eight-phase product.

```bash
cargo run -p sniffer-cli -- demo
```

That runs Appendix D start to finish — capture, save, reopen, decode, show,
select, query, inject loss, replay, export — and reports each step.

## Related repositories

This is one of three that make up the same bench. It decodes; it does not
capture — the hardware half lives in the other two.

| repository | what it is |
|---|---|
| [busbridge-rt](https://github.com/warunafernando/busbridge-rt) | USB bus controller and sniffer on the NXP FRDM-IMXRT1186. The capture source this is pointed at today: I3C at a measured 12.5 MHz, pin-clocked capture lossless to the same rate. |
| [busbridge-stm32h5](https://github.com/warunafernando/busbridge-stm32h5) | The original STM32H5 build. Also the I2C/I3C target the RT1186 board is tested against. |

The coupling runs both ways and is deliberate. `busbridge-rt`'s acceptance
suite shells out to `sniffer.exe` built here — overridable with `SNIFFER_EXE` —
because a capture pipeline whose two halves are only ever tested separately is
a pipeline whose two halves can disagree. The worst defect that project had was
exactly such a disagreement: a reply line truncated in the host library, which
made captures decode to plausible wrong bytes and sent the investigation here,
to a decoder that was faithfully decoding what it had been given.

## What is here

| | |
|---|---|
| `core/schema` | the normalized transaction model, error taxonomy and timestamp model |
| `core/file` | the capture container: records, gaps, recovery, index |
| `core/capture` | raw edges off a BUSBRIDGE board |
| `core/decode` | the decoder SDK: edges, fields, the gap rule |
| `decoders/i2c` | START/STOP, addresses, ACK/NACK, repeated start, clock stretching |
| `decoders/i3c` | CCCs by name, ENTDAA with the address it assigns, IBIs, T-bits |
| `decoders/spi` | all four modes, CS-bounded transfers, word width and bit order |
| `decoders/mdio` | clause 22 and 45, with turnaround checking |
| `decoders/uart` | baud measured or given, parity, framing, a terminal view |
| `decoders/can` | 2.0B standard and extended, stuffing, CRC-15, acknowledge |
| `tools/simulator` | deterministic synthetic traffic for every protocol |
| `core/registry` | which decoder decodes a capture, and how it is configured |
| `analysis/search` | the query language, and the index that answers it |
| `analysis/measure` | interval measurements, transaction comparison, explanations |
| `analysis/extend` | the extension host: device analysers as subprocesses |
| `analysis/trigger` | the trigger model, and where each condition can run |
| `service` | the local API and the MCP tools over it |
| `extensions` | CMIS, PHY and DBC analysers - section 8.1's three examples |
| `api` | the CLI: capture, simulate, decode, show, query, info, replay |
| `ui/desktop` | the desktop analyser: timeline, waveforms, table, inspector |
| `tests/golden` | canonical captures and the exact output they must produce |

The layout is Appendix C's, minus the parts not built yet.

## What each decoder is careful about

Every one of these is a place a generic analyser gets it wrong, and each has a
test named after it.

**I2C** — clock stretching changes nothing, because the decoder is driven by
edges rather than by time. A read's closing NACK is how a read ends, not an
error.

**I3C** — the ninth bit of a data byte is a **T-bit**, not an acknowledge;
reporting it as a NACK is the single most misleading thing an I2C decoder does
to an I3C capture. ENTDAA's discovery data arrives in a second frame after a
repeated START, and is merged into one transaction that names the address it
assigned. A frame opening with a target's own address and the read bit is an
in-band interrupt, and is labelled as one.

**SPI** — the sampling edge is rising when CPOL equals CPHA. Get it wrong and
every byte is shifted by a bit and still looks like data, so `guess_mode` exists
and a test asserts the wrong mode produces different bytes.

**MDIO** — on a read the PHY pulls the second turnaround bit low. A read whose
turnaround never happens is *nothing answered*, not a register reading 0xFFFF,
and the two are reported differently.

**CAN** — bit stuffing means the bits on the wire are not the bits of the frame,
and everything is wrong until they are removed; destuffing stops at the end of
the CRC, because the seven recessive bits of end-of-frame that follow would
otherwise look like a stuffing violation on every correct frame. The CRC and the
acknowledge answer different questions: a good CRC with no acknowledge is a bus
with one node on it, which is the commonest reason a CAN link will not come up,
and it is reported as that rather than as a generic error.

**UART** — the only thing that says where a bit boundary falls is the baud rate,
and getting it wrong produces plausible wrong bytes rather than an error. Bits
are sampled at the middle of their window, the rate can be measured from the
capture, and a framing error says to check the baud rate because that is nearly
always the cause.

## The three contracts Appendix A says to lock early

**Timestamps are picoseconds since the start of the capture, in a `u64`.** Not
ticks: a tick count means nothing without the rate it was counted at, and that
rate belongs to one device. `u64` picoseconds is 213 days at a resolution far
below anything a digital capture resolves.

**A capture file is a magic, a stream of length-prefixed CRC'd records, and an
index.** That framing is what makes it recoverable — a file cut short by a crash
reads until the first record that does not check out, and everything before it
is kept and usable. The index is an optimisation, never the source of truth;
`rebuild_index` derives it from the records.

**The first entry of a sample chunk is the initial state, not a transition.** A
stream of transitions cannot say what the lines were doing before the first one.
This was found the hard way: without it the decoder read the first release of
SDA as a STOP that never happened.

## What the hardware can and cannot do

The specification assumes an FPGA-class capture engine streaming raw samples
with hardware timestamps and sequence numbers. The board here is an
STM32H533 — 250 MHz, USB full speed — and the differences are real:

- **Capture is a burst, not a stream.** 8192 edges into RAM, then read out. That
  is a couple of milliseconds of a busy bus. USB full speed cannot carry a
  400 kHz bus continuously and nothing here pretends otherwise: when the ring
  fills, capture stops, the board says `full=1`, and that becomes a gap record.
- **Two channels.** SCL and SDA, so I2C and I3C. SPI needs four taps, MDIO two
  more, and CAN needs a transceiver the NUCLEO does not carry.
- **Sub-latency pulses are invisible.** A line that goes low and returns between
  two interrupt entries cannot be expressed by a single post-edge sample.

None of that is hidden by the layers above. The capture file is the seam: it
records what was captured and where the holes are, and everything above it works
the same way whether the edges came from a board or from the simulator.

## Using it

```bash
cargo run -p sniffer-cli -- devices
```

```bash
cargo run -p sniffer-cli -- capture cap.cap --self-test
```

`--self-test` drives a known pattern onto the taps and captures it, so the whole
path — pins, both EXTI edges, timestamps, transport, decode — can be checked
with nothing wired. Without it, wire SCL and SDA to the sniffer taps the board
reports in `SNIFF:PINS?` and share a ground with the bus.

```bash
cargo run -p sniffer-cli -- decode cap.cap
```
```bash
cargo run -p sniffer-cli -- show cap.cap --transaction 1
```
```bash
cargo run -p sniffer-cli -- query cap.cap addr:0x52 error:any
```
```bash
cargo run -p sniffer-cli -- query cap.cap addr:0x52 --limit 20 --explain
```

Terms are separated by spaces and all of them must match; a bare word matches
the summary. Numbers are hex with `0x`, binary with `0b`, decimal otherwise.
`sniffer query cap.cap` with no query prints the language, plus the fields that
capture's own decoder emits.

`--limit` stops after that many results without counting the rest, and
`--explain` says how many candidates the index had to examine to produce them -
which is the number that says whether the index is doing its job. On a capture
with two hundred thousand transactions, `addr:0x52 type:READ --limit 20`
examines under two hundred.

```bash
cargo run -p sniffer-cli -- bookmark cap.cap "the nack" --at 1007.5 --note "0x77 never answers"
```
```bash
cargo run -p sniffer-cli -- bookmark cap.cap --list
```
```bash
cargo run -p sniffer-cli -- measure cap.cap --from 10 --to 200
```
```bash
cargo run -p sniffer-cli -- compare cap.cap 1 4
```
```bash
cargo run -p sniffer-cli -- explain cap.cap 5
```

`measure` reports, over the interval: edges and duty cycle per channel, the
effective clock, the narrowest pulse, transaction count and rate, payload bytes
and throughput, and bus utilisation. `compare` lines two transactions up field
by field and marks what differs. `explain` says what one transaction was, drawn
only from its own decoded fields - nothing inferred, the same answer every time.

Bookmarks are annotation records inside the capture, not a sidecar - so
`sniffer info` lists them, the desktop analyser draws them, and a capture sent
to somebody else arrives with them.

The protocol is guessed from the capture's channel names and `--protocol`
overrides it. The one case a guess cannot settle is I2C against I3C: they share
both wires and most of their framing, so an I3C capture needs
`--protocol i3c` — otherwise it decodes as readable I2C with the wrong labels.

Per-protocol settings a capture cannot carry:

```bash
sniffer decode cap.cap --protocol uart --uart-baud 115200 --uart-parity e
```
```bash
sniffer decode cap.cap --protocol spi --spi-mode 3 --spi-bits 16
```
```bash
sniffer decode cap.cap --protocol can --can-bitrate 500000
```

No hardware needed for any of this:

```bash
cargo run -p sniffer-cli -- simulate cap.cap --script demo --gap
```

## The desktop analyser

```bash
cargo run -p sniffer-ui
```
```bash
cargo run -p sniffer-ui -- --simulate demo
```
```bash
cargo run -p sniffer-ui -- --self-test
```
```bash
cargo run -p sniffer-ui -- tests/golden/board.cap
```

The window is one layout, not a set of tabs: the whole-capture strip at the top,
the waveforms and decode bubbles under it, the transaction table below that, and
the inspector down the right. Selection is shared - clicking a bubble scrolls
the table to its row, clicking a row selects the bubble, and clicking a field in
the inspector puts the timeline on the samples that field was read from. That
last one is the point of the whole window: a decode you cannot check against the
waveform is a claim rather than evidence.

| | |
|---|---|
| drag | pan |
| wheel | zoom, anchored on the pointer |
| `+` `-` | zoom about the centre |
| `F` | fit the whole capture |
| left, right | pan by an eighth of a screen |
| `Home` | back to the start |
| `N`, `P` | the next and previous result, zoomed to |
| `B` | bookmark where the pointer is |
| `A` | drop the next measurement cursor (or right-click the timeline) |
| `C` | put the cursors away |

`N` and `P` walk whatever the filter currently matches - with no filter, every
transaction. That is deliberate: the keys, the table, the filter box and the
CLI then all mean the same thing by "the results", and errors-only is the
`errors` preset rather than a fourth definition of what counts as a problem.
(It is the same definition `sniffer decode` counts: any error, or an incomplete
transaction. Not a severity threshold - a NACK is severity `notice`, and it is
the thing people are looking for.)

The filter box takes the same query language as `sniffer query`, against the
same parser, planned against the same index. Typing a partial word offers the
fields this decode actually carried, then the ones its decoder can emit, then
the language's own terms - so `can.id` is offered on a CAN capture and not on
an I2C one. `errors` and `clean` are one click, as is one button per bus when a
capture has more than one. A query can be given a name and kept: saved searches
live in `%APPDATA%\sniffer\workspace.tsv` (or `$XDG_CONFIG_HOME/sniffer/`) and
come back next session; right-click one to forget it.

Bookmarks are `B`, or the button in the session pane. They mark a place to come
back to, are drawn on both the timeline and the overview strip, and are written
into the capture file when it is saved - the same records the CLI's `bookmark`
command reads and writes.

The protocol selector and the per-protocol settings beside it are the same
registry the CLI's `--protocol` and `--uart-baud` reach.

Two cursors make a measurement. Drop them with a right-click on the timeline
(or `A` at the pointer) and the strip under the waveform reads out the interval:
delta time and its frequency, edges, effective clock and duty cycle per channel,
transactions and how many of them went wrong, payload throughput, and what
fraction of the interval carried traffic. It is the same `measure` the CLI runs
over the same interval, so the two cannot disagree.

The inspector explains the selection from its own fields, and "Pin to compare"
holds one transaction aside: select another and the two are lined up field by
field with the differences marked. Both are `analysis/measure`, so `sniffer
compare` and `sniffer explain` produce the same answers in a terminal.

Some numbers there have an obvious-looking wrong definition, so: edges are
transitions *of that channel* (not capture entries, which include every other
channel's edges); high time is integrated from the holds, so a level already
high when the interval opened counts from the interval's start; the effective
clock is the **median** period between rising edges, because on a stretched
bus the mean reports a clock nobody ran at; and utilisation is the *union* of
transaction spans, because a transaction overlaps its own parts and summing
durations would cheerfully report 300% busy.

The traffic is drawn from the capture's transitions, so what is on screen is the
recorded edges rather than a resampled picture of them. Zoomed out far enough
that several transitions share a pixel column, that column becomes a band from
the lowest to the highest level in it - the honest low-zoom picture, per column,
so a quiet stretch beside a busy one still shows its edges. Gaps are drawn
across the full height of every channel, because a hole in the capture changes
how everything above it should be read.

Section 3.2 of the specification recommends Qt6 or Tauri; this is egui, on
purpose. It is GPU-backed, it is already proven against these same
waveform-drawing problems in the BUSBRIDGE bench console next door, and it keeps
the product in one language with no IPC boundary between the UI and the decoders
it calls thousands of times a frame. The requirements that actually matter for
this phase - sixty frames a second while panning, and one implementation of the
decoders shared with the CLI - are met either way.

## Device analysers

Section 8's pipeline: transactions in, derived fields and semantic labels out.

```bash
cargo run -p sniffer-cli -- extensions
```
```bash
cargo run -p sniffer-cli -- analyze cap.cap
```
```bash
cargo run -p sniffer-cli -- analyze cap.cap --extension cmis --set page=0x11 --save
```

Three ship, which are section 8.1's own examples:

| | |
|---|---|
| `cmis` | an I2C transfer to an optical module: page, register, and 0x1A 0x31 as 26.191 C |
| `phy` | an MDIO access as BMCR or BMSR, with the bits named and the link state read out |
| `dbc` | a CAN frame as named signals in engineering units, from a signal database |

An extension is a directory with an `extension.json` and a program to run. It
reads one JSON object per line on stdin - a hello with the protocol and its
settings, then one transaction per line - and writes lines back naming the
fields, labels and warnings it wants added. That is the whole API: an extension
never sees the raw capture and cannot draw, which is what section 8 asks for
and what makes running somebody else's safe.

It is a subprocess rather than an embedded interpreter for a reason section 8.2
states as a requirement: CPU, time and memory limits, and clear failure
reporting. A subprocess can be timed out and killed, its output can be capped,
and its crash is a report rather than a lost capture. The tests hold it to
that: an extension that spins is stopped and reported, one that floods its
output is cut off, and one that raises is reported with its own message.

Two rules the host enforces, because an extension that could break them could
hide a fault:

- **It cannot overwrite a decoder's field.** A name that already exists is
  namespaced under the extension's own name. The decoder's account of the wire
  wins.
- **It cannot lower a severity.** Warnings raise; nothing quietens. An
  extension that could quieten a NACK would be a way to hide one.

## Triggers

```bash
cargo run -p sniffer-cli -- trigger cap.cap error:nack --out around.cap
```
```bash
cargo run -p sniffer-cli -- trigger cap.cap "addr:0x3C then error:nack within=1ms"
```
```bash
cargo run -p sniffer-cli -- monitor --self-test --until addr:0x50 --repeat 5
```

One condition language, covering section 10's classes:

| | |
|---|---|
| `edge:rising:0`, `edge:0` | edge |
| `high:1`, `low:1:for=2us` | level, optionally held |
| `glitch:0:shorter=100ns` | pulse width - a glitch, or a stretched clock |
| `start`, `start:i2c` | the framing a transaction begins with |
| `addr:0x52`, `type:IBI` | a protocol field, read by the same parser as the search box |
| `error:nack`, `error:any` | an error |
| `A then B within=5ms` | a sequence, reported at the second event |

Spaces mean and, commas mean or.

The builder says two different things about a condition and does not conflate
them: which of section 10's classes it belongs to, and hence whether a capture
engine *could* arm it; and where it is actually being evaluated. On this board
the second answer is always "in software, over the captured samples", because
`SNIFF:RAW:*` captures every edge into a ring and hands it over with no
condition to arm. That is also why the pre-trigger window is free: the samples
before the match were captured too, so `--out` clips them out - which is what a
hardware trigger needs a ring buffer for.

`monitor` is the live half. Burst hardware cannot decode while it captures, so
a live session is a sequence of bursts, each decoded as it lands, stopping when
the condition matches. The time between two bursts is time nobody watched, and
it becomes a gap record - the same rule as everywhere else, so a monitored
session cannot claim to have seen something it did not.

## The API, and MCP

```bash
cargo run -p sniffer-cli -- api
```
```bash
cargo run -p sniffer-cli -- serve
```
```bash
cargo run -p sniffer-cli -- serve --allow-control
```

Section 9's surface, in `service`: `list_devices`, `configure_capture`,
`start_capture`, `stop_capture`, `open_capture`, `add_decoder`, `query`,
`get_transaction`, `get_waveform`, `export`, `add_bookmark`, `capture_health`,
plus `compare_transactions`, `first_error_after` and `summarize_interval` for
section 9.2's agent tools. They are the same crates the window calls, so an
agent and a person see the same decode rather than two implementations that
agree today.

`serve` speaks MCP over stdin and stdout. **The control tools are not exposed
unless the server was started with `--allow-control`**: `tools/list` omits
them and calling one is refused with the reason. Section 9.2 requires that
actions changing capture configuration or hardware state be explicit, and a
flag at start-up is explicit in a way a per-call prompt is not - a prompt is
something people click through, and a tool that is not listed is one an agent
cannot talk its way into.

`export evidence` writes what section 9.2 calls a reproducible evidence
package: the query, the transaction ids, the decoder and its settings, and a
capture clipped to exactly the samples involved. Somebody else can run the same
query over the same samples and get the same answer, which is the difference
between evidence and a screenshot.

An agent with no hardware is not stuck: `open_capture` takes a simulator script
name as well as a path, so `{"path": "optics"}` gives it a real capture to work
on.

## Packaging

```powershell
scripts\package.ps1
```

Builds release, runs the tests, and stages `dist\sniffer-<version>\` with both
executables, the extensions beside them, the golden corpus, a `build.json`
saying what the build was made from, and a SHA-256 of every file. It refuses to
package if the tests fail.

Nothing checks for updates by itself - a bench tool that phones home is a bench
tool people stop trusting. `sniffer version` prints what the copy is, including
the build manifest when there is one beside the executable, which is what makes
"is this current?" answerable.

## The golden corpus

```bash
cargo test
```

`tests/golden/*.json` is the exact decoded output of each canonical capture. A
change to a decoder that alters any of it fails the test with the first line
that differs. To accept a change, read the diff and then:

```bash
UPDATE_GOLDEN=1 cargo test -p sniffer-cli --test golden
```

`board.cap` is in there deliberately: it came off real hardware, so the
timestamps fall where interrupt latency actually put them rather than where the
protocol says they should. A decoder that has only met generated traffic has not
met an interrupt.

## What is not built

Honestly, because the specification is a product and this is its first phase:

- **No hardware trigger.** The firmware has no comparator to arm: it captures
  every edge into a ring and hands the ring over. Every trigger is evaluated
  over the captured samples, and the builder says so rather than implying
  otherwise. The model already marks which conditions a capture engine could
  arm, so the day the firmware grows one there is one function to change.
- **Live capture is repeated bursts, not a stream.** `monitor` decodes each
  burst as it lands and records the unwatched time between them as gaps. USB
  full speed cannot carry a busy 400 kHz bus continuously, and nothing here
  pretends otherwise.
- **Extensions get time and output limits, not a sandbox.** They are killed
  when they run long and cut off when they flood, and they cannot reach the
  capture or the window. They are still ordinary subprocesses with the
  privileges of whoever ran the analyser: read an extension before you run it,
  the same as any other program.
- **No protocol-aware timing checks.** `measure` reports what the edges did;
  it does not know that I2C fast mode wants a minimum 1.3 us bus-free time.
  Those rule tables would sit beside the device analysers.
- **The DBC analyser reads a JSON signal table, not a `.dbc` file.** The fields
  are the ones a DBC describes, so converting one is mechanical, but the parser
  is not written.
- **CAN-FD.** CAN 2.0B is done. FD moves the CRC to 17 or 21 bits with a
  stuff-bit counter, changes the DLC encoding above 8, and switches bit rate
  mid-frame at BRS - so an FD frame is detected, labelled, its identifier
  decoded, and its payload left alone rather than guessed at. The NUCLEO also
  has no CAN transceiver, so CAN captures come from the simulator.
- **Clause 45 sequencing.** MDIO decodes each frame on its own; pairing an
  address frame with the data frame that follows it is a later pass.
- **HDR modes for I3C.** SDR only, and an HDR pattern shows as a framing error
  rather than as confident nonsense.
- **Whole-file reading.** Captures larger than RAM need a chunked reader. The
  format is built for it — records are independent and the index maps chunk ids
  to byte offsets — so that is an addition rather than a redesign.
- **Hardware capture is Windows-only.** The capture crate links the BUSBRIDGE
  C library, which talks WinUSB. Everything else - the file format, the
  decoders, the search index, the measurements, the extensions, the window -
  is portable Rust and builds anywhere, but only Windows has been run.
- **Accessibility is partial.** Every action in the window has a key or a
  button, nothing is conveyed by colour alone (severity appears as text in the
  table and the inspector as well as in the palette), and the marks on the
  timeline are held distinct by a test. Screen-reader support is whatever egui
  provides, and has not been tested.
- **The index is in memory, not in the file.** Section 4.4 suggests SQLite or a
  columnar store on disk; this is the columnar half, built from a decode in one
  pass and thrown away with it. Building it costs one pass over the decode, so
  for a burst capture that is nothing - a capture too large to decode in RAM
  needs the chunked reader above before an on-disk index would help.
- **Data bytes and text are not indexed.** `data:"DE AD"` is a byte pattern and
  `contains:"ERROR"` a substring, and both are checked against the candidates
  the other terms produced. Correct either way; a suffix index for text is a
  later phase.
- **No OR, no negation, no parentheses in queries.** Every example in the
  specification is a conjunction. The parser refuses an unknown field rather
  than silently matching everything.
