//! MCP over stdio: the session as tools an agent can call.
//!
//! Section 9.2 lists the tools an engineering agent needs - open and control
//! captures, search for events and errors, fetch a transaction with its
//! neighbours, compare two of them, find the first error after an event,
//! summarise an interval, and export a reproducible evidence package. They are
//! [`Session`]'s methods, so an agent and a person are looking at the same
//! decode rather than at two implementations that agree today.
//!
//! # The safety boundary is a command-line flag
//!
//! Section 9.2 requires that actions changing capture configuration or
//! hardware state be explicit. The control tools are not exposed at all unless
//! the server was started with `--allow-control`: `tools/list` omits them and
//! `tools/call` refuses them with an explanation. That makes permission a
//! decision somebody takes once, deliberately, rather than a prompt to click
//! through - and an agent cannot talk its way past a tool that is not there.
//!
//! # The protocol, minimally and correctly
//!
//! JSON-RPC 2.0 over stdin and stdout, one message per line. `initialize`,
//! `tools/list`, `tools/call`, and the notifications that go with them.
//! Nothing else is needed to be a useful MCP server, and anything else would
//! be guessing at a client's requirements.
//!
//! Errors come back as results with `isError` set rather than as JSON-RPC
//! errors, because a tool that could not do what was asked is a normal outcome
//! an agent should read and act on - the transport is fine.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde_json::{json, Value};

use crate::{Kind, Session};

/// What this server calls itself.
pub const SERVER_NAME: &str = "sniffer";

/// The MCP revision this speaks. Clients send their own; this one answers with
/// what it implements rather than echoing theirs, so a mismatch is visible.
pub const PROTOCOL_VERSION: &str = "2024-11-05";

/// One tool, and which half of the boundary it is on.
struct Tool {
    name: &'static str,
    kind: Kind,
    about: &'static str,
    schema: fn() -> Value,
}

fn no_arguments() -> Value {
    json!({ "type": "object", "properties": {}, "additionalProperties": false })
}

const TOOLS: &[Tool] = &[
    Tool {
        name: "list_devices",
        kind: Kind::Read,
        about: "The BUSBRIDGE boards attached to this machine.",
        schema: no_arguments,
    },
    Tool {
        name: "capture_health",
        kind: Kind::Read,
        about: "What the session holds and whether it can be trusted: \
                transitions, span, gaps, truncation, decoder, and how many \
                transactions have something wrong with them.",
        schema: no_arguments,
    },
    Tool {
        name: "open_capture",
        kind: Kind::Read,
        about: "Load a capture file into the session and decode it. Also \
                accepts a simulator script name (demo, scan, uart, spi, mdio, \
                i3c, can, optics, stretch, truncated) to work without \
                hardware.",
        schema: || json!({
            "type": "object",
            "properties": {
                "path": { "type": "string",
                          "description": "a .cap file, or a simulator script name" },
                "hz": { "type": "integer",
                        "description": "tick base for a simulated script" }
            },
            "required": ["path"]
        }),
    },
    Tool {
        name: "add_decoder",
        kind: Kind::Read,
        about: "Decode the session's capture as a protocol. Without one the \
                protocol is guessed from the channel names, which cannot \
                separate I2C from I3C - they share both wires.",
        schema: || json!({
            "type": "object",
            "properties": {
                "protocol": { "type": "string",
                              "enum": ["i2c", "i3c", "spi", "mdio", "uart", "can"] },
                "settings": {
                    "type": "object",
                    "description": "decoder settings a capture cannot carry, \
                                    e.g. {\"uart_parity\": \"e\"}, \
                                    {\"spi_mode\": \"3\"}, \
                                    {\"can_bitrate\": \"500000\"}",
                    "additionalProperties": { "type": "string" }
                }
            }
        }),
    },
    Tool {
        name: "query",
        kind: Kind::Read,
        about: "Find transactions. Terms are separated by spaces and all must \
                match: addr:0x52, type:WRITE, bus:0, protocol:i2c, error:any, \
                error:nack, severity:warning, data:\"DE AD\", \
                contains:text, incomplete:true. Numbers take 0x, 0b or \
                decimal. A bare word matches the summary.",
        schema: || json!({
            "type": "object",
            "properties": {
                "expression": { "type": "string" },
                "start_ps": { "type": "integer" },
                "end_ps": { "type": "integer" },
                "limit": { "type": "integer" }
            },
            "required": ["expression"]
        }),
    },
    Tool {
        name: "get_transaction",
        kind: Kind::Read,
        about: "One transaction: its fields, a derived explanation, the \
                transactions either side of it, its parent and its parts, and \
                the sample range every field came from.",
        schema: || json!({
            "type": "object",
            "properties": { "id": { "type": "integer" } },
            "required": ["id"]
        }),
    },
    Tool {
        name: "get_waveform",
        kind: Kind::Read,
        about: "The raw transitions over a time range, per channel, with the \
                level each channel held when the range opened. This is the \
                evidence a decode is a claim about.",
        schema: || json!({
            "type": "object",
            "properties": {
                "start_ps": { "type": "integer" },
                "end_ps": { "type": "integer" },
                "channels": { "type": "array", "items": { "type": "integer" } },
                "limit": { "type": "integer" }
            },
            "required": ["start_ps", "end_ps"]
        }),
    },
    Tool {
        name: "compare_transactions",
        kind: Kind::Read,
        about: "Two transactions, field by field, with the differences marked.",
        schema: || json!({
            "type": "object",
            "properties": {
                "a": { "type": "integer" },
                "b": { "type": "integer" }
            },
            "required": ["a", "b"]
        }),
    },
    Tool {
        name: "first_error_after",
        kind: Kind::Read,
        about: "The first transaction with a problem after a named event. The \
                event is a trigger condition: addr:0x52, type:CCC, \
                edge:rising:0, start:i2c.",
        schema: || json!({
            "type": "object",
            "properties": { "event": { "type": "string" } },
            "required": ["event"]
        }),
    },
    Tool {
        name: "summarize_interval",
        kind: Kind::Read,
        about: "Measurements over a time range: edges and duty cycle per \
                channel, effective clock, transaction count and rate, payload \
                throughput, bus utilisation, and whether a gap touches it.",
        schema: || json!({
            "type": "object",
            "properties": {
                "start_ps": { "type": "integer" },
                "end_ps": { "type": "integer" }
            },
            "required": ["start_ps", "end_ps"]
        }),
    },
    Tool {
        name: "find_trigger",
        kind: Kind::Read,
        about: "Where a trigger condition happened: edge:rising:0, \
                low:1:for=2us, glitch:0:shorter=100ns, start:i2c, addr:0x52, \
                error:nack, or `A then B within=5ms`. Evaluated over the \
                captured samples.",
        schema: || json!({
            "type": "object",
            "properties": { "condition": { "type": "string" } },
            "required": ["condition"]
        }),
    },
    Tool {
        name: "export",
        kind: Kind::Read,
        about: "json or csv of the matching transactions, or `evidence` - a \
                directory holding the query, the transaction ids, the decoder \
                and its settings, and a capture clipped to the samples \
                involved, so somebody else can reproduce the finding.",
        schema: || json!({
            "type": "object",
            "properties": {
                "format": { "type": "string", "enum": ["json", "csv", "evidence"] },
                "query": { "type": "string" },
                "out": { "type": "string",
                         "description": "directory for an evidence package" }
            },
            "required": ["format"]
        }),
    },
    Tool {
        name: "add_bookmark",
        kind: Kind::Read,
        about: "Mark a time in the session's capture. It reaches the file only \
                when the session is saved.",
        schema: || json!({
            "type": "object",
            "properties": {
                "at_ps": { "type": "integer" },
                "label": { "type": "string" },
                "note": { "type": "string" }
            },
            "required": ["at_ps", "label"]
        }),
    },
    Tool {
        name: "save_capture",
        kind: Kind::Read,
        about: "Write the session's capture, its bookmarks and its decode to a \
                file.",
        schema: || json!({
            "type": "object",
            "properties": { "path": { "type": "string" } },
            "required": ["path"]
        }),
    },
    // ---- control: hardware and capture configuration ----
    Tool {
        name: "configure_capture",
        kind: Kind::Control,
        about: "CHANGES CAPTURE CONFIGURATION. Set the port, edge count, burst \
                length, self-test mode, and a trigger to stop at.",
        schema: || json!({
            "type": "object",
            "properties": {
                "port": { "type": "string" },
                "max_edges": { "type": "integer" },
                "settle_ms": { "type": "integer" },
                "self_test": { "type": "boolean",
                               "description": "drive the board's own taps and \
                                               capture the result - the only \
                                               way to get edges with nothing \
                                               wired" },
                "until": { "type": "string",
                           "description": "a trigger condition to stop at" },
                "rounds": { "type": "integer",
                            "description": "how many bursts to take" }
            }
        }),
    },
    Tool {
        name: "start_capture",
        kind: Kind::Control,
        about: "CHANGES HARDWARE STATE. Arm the board and take a burst, \
                blocking until it has been drained, then decode it. Replaces \
                whatever the session held.",
        schema: no_arguments,
    },
    Tool {
        name: "stop_capture",
        kind: Kind::Control,
        about: "CHANGES HARDWARE STATE. This board captures in bursts, so \
                start_capture returns when its burst is done and there is \
                nothing left running to stop.",
        schema: no_arguments,
    },
];

/// Run the server until stdin closes.
///
/// `allow_control` exposes the tools that touch hardware or capture
/// configuration. Without it they are not listed and calling one is refused.
pub fn serve(allow_control: bool) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    let mut session = Session::new();

    for line in stdin.lock().lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(line) {
            Ok(value) => value,
            Err(e) => {
                // A parse failure is a transport error, which is one of the
                // few things that is genuinely a JSON-RPC error.
                write(&mut out, &json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("{e}") }
                }))?;
                continue;
            }
        };

        // A notification has no id and takes no answer.
        let id = request.get("id").cloned();
        let method = request.get("method").and_then(|m| m.as_str())
            .unwrap_or("");
        let params = request.get("params").cloned().unwrap_or(json!({}));

        let answer = dispatch(&mut session, allow_control, method, &params);
        let Some(id) = id else { continue };

        match answer {
            Some(Ok(result)) => write(&mut out, &json!({
                "jsonrpc": "2.0", "id": id, "result": result }))?,
            Some(Err(message)) => write(&mut out, &json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": message } }))?,
            None => {}
        }
    }
    Ok(())
}

fn write(out: &mut impl Write, value: &Value) -> std::io::Result<()> {
    writeln!(out, "{value}")?;
    out.flush()
}

/// Answer one request. `None` means "no answer expected".
fn dispatch(
    session: &mut Session,
    allow_control: bool,
    method: &str,
    params: &Value,
) -> Option<Result<Value, String>> {
    match method {
        "initialize" => Some(Ok(json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": { "tools": {} },
            "serverInfo": {
                "name": SERVER_NAME,
                "version": env!("CARGO_PKG_VERSION"),
            },
            "instructions": instructions(allow_control),
        }))),
        "notifications/initialized" | "notifications/cancelled" => None,
        "ping" => Some(Ok(json!({}))),
        "tools/list" => Some(Ok(json!({ "tools": tool_list(allow_control) }))),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let arguments = params.get("arguments").cloned().unwrap_or(json!({}));
            Some(Ok(call(session, allow_control, name, &arguments)))
        }
        // Enumerations a client may ask for whether or not the server has
        // them; an empty list is the correct answer, not an error.
        "resources/list" => Some(Ok(json!({ "resources": [] }))),
        "prompts/list" => Some(Ok(json!({ "prompts": [] }))),
        other => Some(Err(format!("this server does not implement {other:?}"))),
    }
}

fn instructions(allow_control: bool) -> String {
    let mut text = String::from(
        "A multi-protocol bus analyser: I2C, I3C, SPI, MDIO, UART and CAN.\n\n\
         Open a capture (or a simulator script name, to work without \
         hardware), then query it. Every decoded field carries the sample \
         range it came from, so a claim about the bus can always be checked \
         against get_waveform.\n\n\
         What the tools will not do: guess. A protocol that cannot be told \
         from the channel names is reported as guessed; a transaction that ran \
         into a gap or the end of the capture is marked incomplete rather than \
         completed; a capture with holes says so in capture_health.\n\n");
    if allow_control {
        text.push_str(
            "Capture control is enabled: configure_capture and start_capture \
             will arm the attached board. start_capture blocks for the burst \
             length and replaces what the session holds.");
    } else {
        text.push_str(
            "Capture control is disabled, so no tool here can touch the \
             hardware or change capture configuration. The person running this \
             server can enable it with --allow-control.");
    }
    text
}

fn tool_list(allow_control: bool) -> Vec<Value> {
    TOOLS.iter()
        .filter(|t| allow_control || t.kind == Kind::Read)
        .map(|t| json!({
            "name": t.name,
            "description": t.about,
            "inputSchema": (t.schema)(),
        }))
        .collect()
}

/// The result envelope MCP expects: content, and whether it is a failure.
fn text(body: String, failed: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": body }],
        "isError": failed,
    })
}

fn ok(value: impl serde::Serialize) -> Value {
    match serde_json::to_string_pretty(&value) {
        Ok(body) => text(body, false),
        Err(e) => text(format!("could not serialise the result: {e}"), true),
    }
}

fn call(session: &mut Session, allow_control: bool, name: &str, args: &Value)
    -> Value
{
    let Some(tool) = TOOLS.iter().find(|t| t.name == name) else {
        return text(format!(
            "no tool called {name:?}. tools/list says what there is."), true);
    };
    if tool.kind == Kind::Control && !allow_control {
        // The boundary, enforced rather than documented.
        return text(format!(
            "{name} changes capture configuration or hardware state, and this \
             server was started without --allow-control. Ask the person \
             running it to restart with that flag if you should be able to \
             arm the board."), true);
    }

    let string = |key: &str| args.get(key).and_then(|v| v.as_str());
    let number = |key: &str| args.get(key).and_then(|v| v.as_u64());

    match name {
        "list_devices" => {
            let devices = Session::list_devices();
            if devices.is_empty() {
                // A blunt answer, with the reason people usually need.
                text("no boards attached. The board's own USB connector needs \
                      a cable to this machine; the ST-LINK cable carries debug \
                      only. Open a simulator script instead - try \
                      open_capture with \"demo\".".into(), false)
            } else {
                ok(devices)
            }
        }
        "capture_health" => ok(session.capture_health()),
        "open_capture" => {
            let Some(path) = string("path") else {
                return text("open_capture needs a path".into(), true);
            };
            // A script name rather than a file: how an agent works without
            // hardware, and it is the same corpus the tests use.
            if let Some(script) = simulator::script_named(path) {
                let hz = number("hz").unwrap_or(match script.protocol {
                    schema::Protocol::Uart => 115_200,
                    schema::Protocol::Can => 500_000,
                    _ => 1_000_000,
                });
                match simulator::build(path, hz) {
                    Some(capture) => {
                        session.adopt(capture, None);
                        let mut settings = std::collections::BTreeMap::new();
                        for (k, v) in script.settings {
                            settings.insert(k.to_string(), v.to_string());
                        }
                        match session.add_decoder(
                            Some(script.protocol.as_str()), &settings)
                        {
                            Ok(report) => ok(json!({
                                "opened": format!("simulated script {path}"),
                                "decode": report,
                                "health": session.capture_health(),
                            })),
                            Err(e) => text(e, true),
                        }
                    }
                    None => text(format!("script {path:?} produced nothing"), true),
                }
            } else {
                match session.open_capture(&PathBuf::from(path)) {
                    Ok(health) => ok(health),
                    Err(e) => text(e, true),
                }
            }
        }
        "add_decoder" => {
            let mut settings = std::collections::BTreeMap::new();
            if let Some(map) = args.get("settings").and_then(|v| v.as_object()) {
                for (k, v) in map {
                    let value = match v {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    settings.insert(k.clone(), value);
                }
            }
            match session.add_decoder(string("protocol"), &settings) {
                Ok(report) => ok(report),
                Err(e) => text(e, true),
            }
        }
        "query" => {
            let Some(expression) = string("expression") else {
                return text("query needs an expression".into(), true);
            };
            let range = match (number("start_ps"), number("end_ps")) {
                (Some(a), Some(b)) => Some((a, b)),
                _ => None,
            };
            match session.query(expression, range,
                                number("limit").map(|n| n as usize))
            {
                Ok(result) => ok(result),
                Err(e) => text(e, true),
            }
        }
        "get_transaction" => match number("id") {
            None => text("get_transaction needs an id".into(), true),
            Some(id) => match session.get_transaction(id) {
                Ok(detail) => ok(detail),
                Err(e) => text(e, true),
            },
        },
        "get_waveform" => {
            let (Some(start), Some(end)) = (number("start_ps"), number("end_ps"))
            else {
                return text("get_waveform needs start_ps and end_ps".into(), true);
            };
            let channels: Option<Vec<u8>> = args.get("channels")
                .and_then(|v| v.as_array())
                .map(|list| list.iter()
                    .filter_map(|v| v.as_u64())
                    .map(|n| n as u8)
                    .collect());
            match session.get_waveform(start, end, channels.as_deref(),
                                       number("limit").map(|n| n as usize))
            {
                Ok(wave) => ok(wave),
                Err(e) => text(e, true),
            }
        }
        "compare_transactions" => {
            let (Some(a), Some(b)) = (number("a"), number("b")) else {
                return text("compare_transactions needs a and b".into(), true);
            };
            match session.compare_transactions(a, b) {
                Ok(value) => ok(value),
                Err(e) => text(e, true),
            }
        }
        "first_error_after" => match string("event") {
            None => text("first_error_after needs an event".into(), true),
            Some(event) => match session.first_error_after(event) {
                Ok(value) => ok(value),
                Err(e) => text(e, true),
            },
        },
        "summarize_interval" => {
            let (Some(start), Some(end)) = (number("start_ps"), number("end_ps"))
            else {
                return text("summarize_interval needs start_ps and end_ps"
                            .into(), true);
            };
            match session.summarize_interval(start, end) {
                Ok(value) => ok(value),
                Err(e) => text(e, true),
            }
        }
        "find_trigger" => {
            let Some(condition) = string("condition") else {
                return text("find_trigger needs a condition".into(), true);
            };
            let Some(capture) = session.capture() else {
                return text("no capture is open".into(), true);
            };
            match trigger::parse(condition) {
                Err(e) => text(e, true),
                Ok(parsed) => {
                    let hits = trigger::find(capture, session.decoded(), &parsed);
                    ok(json!({
                        "condition": parsed.describe(),
                        "class": parsed.class().as_str(),
                        "could_run_in_hardware": parsed.hardware_class(),
                        "evaluated": "in software, over the captured samples",
                        "matches": hits.iter().map(|m| json!({
                            "at_ps": m.at,
                            "what": m.what,
                            "transaction": m.transaction,
                        })).collect::<Vec<_>>(),
                    }))
                }
            }
        }
        "export" => {
            let format = string("format").unwrap_or("json");
            let out = string("out").map(PathBuf::from);
            match session.export(format, string("query"), out.as_deref()) {
                Ok(body) => text(body, false),
                Err(e) => text(e, true),
            }
        }
        "add_bookmark" => {
            let (Some(at), Some(label)) = (number("at_ps"), string("label"))
            else {
                return text("add_bookmark needs at_ps and label".into(), true);
            };
            match session.add_bookmark(at, label, string("note").unwrap_or("")) {
                Ok(count) => text(format!("bookmarked; the session now has \
                                           {count}"), false),
                Err(e) => text(e, true),
            }
        }
        "save_capture" => match string("path") {
            None => text("save_capture needs a path".into(), true),
            Some(path) => match session.save(&PathBuf::from(path)) {
                Ok(()) => text(format!("wrote {path}"), false),
                Err(e) => text(e, true),
            },
        },
        "configure_capture" => {
            let mut config = session.configuration().clone();
            if let Some(port) = string("port") {
                config.port = Some(port.to_string());
            }
            if let Some(n) = number("max_edges") {
                config.max_edges = n as u32;
            }
            if let Some(n) = number("settle_ms") {
                config.settle_ms = n;
            }
            if let Some(b) = args.get("self_test").and_then(|v| v.as_bool()) {
                config.self_test = b;
            }
            if let Some(until) = string("until") {
                config.until = Some(until.to_string());
            }
            if let Some(n) = number("rounds") {
                config.rounds = n as u32;
            }
            match session.configure_capture(config) {
                Ok(config) => ok(config),
                Err(e) => text(e, true),
            }
        }
        "start_capture" => match session.start_capture() {
            Ok(health) => ok(health),
            Err(e) => text(e, true),
        },
        "stop_capture" => text(session.stop_capture(), false),
        _ => text(format!("{name} is listed but not implemented"), true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ask(session: &mut Session, control: bool, method: &str, params: Value)
        -> Value
    {
        dispatch(session, control, method, &params)
            .expect("a request should be answered")
            .expect("and not be a transport error")
    }

    fn call_tool(session: &mut Session, control: bool, name: &str, args: Value)
        -> Value
    {
        ask(session, control, "tools/call",
            json!({ "name": name, "arguments": args }))
    }

    /// The body of a successful call, parsed back.
    fn body(result: &Value) -> Value {
        assert_eq!(result["isError"], json!(false),
                   "the call failed: {}", result["content"][0]["text"]);
        let text = result["content"][0]["text"].as_str().unwrap();
        serde_json::from_str(text).unwrap_or(json!(text))
    }

    fn opened() -> Session {
        let mut session = Session::new();
        let result = call_tool(&mut session, false, "open_capture",
                               json!({ "path": "demo" }));
        assert_eq!(result["isError"], json!(false));
        session
    }

    #[test]
    fn initialize_says_what_it_is_and_what_it_will_not_do() {
        let mut session = Session::new();
        let result = ask(&mut session, false, "initialize", json!({}));
        assert_eq!(result["protocolVersion"], json!(PROTOCOL_VERSION));
        assert_eq!(result["serverInfo"]["name"], json!("sniffer"));
        assert!(result["capabilities"]["tools"].is_object());

        let instructions = result["instructions"].as_str().unwrap();
        assert!(instructions.contains("guess"),
                "an agent has to be told what the tools refuse to do");
        assert!(instructions.contains("--allow-control"),
                "and how capture control is enabled");
    }

    /// The boundary section 9.2 requires: control tools are not there at all
    /// unless somebody said they may be.
    #[test]
    fn control_tools_are_absent_until_they_are_allowed() {
        let mut session = Session::new();

        let listed = ask(&mut session, false, "tools/list", json!({}));
        let names: Vec<&str> = listed["tools"].as_array().unwrap().iter()
            .map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"query"));
        assert!(!names.contains(&"start_capture"),
                "a control tool was listed on a read-only server");

        let refused = call_tool(&mut session, false, "start_capture", json!({}));
        assert_eq!(refused["isError"], json!(true));
        let why = refused["content"][0]["text"].as_str().unwrap();
        assert!(why.contains("--allow-control"), "unhelpful refusal: {why}");

        let listed = ask(&mut session, true, "tools/list", json!({}));
        let names: Vec<&str> = listed["tools"].as_array().unwrap().iter()
            .map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"start_capture"));
    }

    /// Every control tool has to shout about it in its own description: a
    /// client that only shows descriptions must still make the boundary
    /// visible.
    #[test]
    fn every_control_tool_says_so_in_its_description() {
        for tool in TOOLS.iter().filter(|t| t.kind == Kind::Control) {
            assert!(tool.about.contains("CHANGES"),
                    "{} does not announce that it changes state", tool.name);
        }
        for tool in TOOLS.iter().filter(|t| t.kind == Kind::Read) {
            assert!(!tool.about.contains("CHANGES"),
                    "{} claims to change state but is listed as read-only",
                    tool.name);
        }
    }

    /// Section 9.2's list, all present as tools.
    #[test]
    fn the_tools_cover_what_section_nine_asks_for() {
        let names: Vec<&str> = TOOLS.iter().map(|t| t.name).collect();
        for wanted in ["open_capture", "start_capture", "stop_capture",
                       "query", "get_transaction", "compare_transactions",
                       "first_error_after", "summarize_interval", "export",
                       "get_waveform", "add_bookmark", "capture_health",
                       "list_devices", "configure_capture"] {
            assert!(names.contains(&wanted), "{wanted} is missing");
        }
        // And every tool's schema is a well-formed object schema.
        for tool in TOOLS {
            let schema = (tool.schema)();
            assert_eq!(schema["type"], json!("object"), "{}", tool.name);
            assert!(schema["properties"].is_object(), "{}", tool.name);
            assert!(!tool.about.is_empty(), "{}", tool.name);
        }
    }

    #[test]
    fn a_simulator_script_opens_without_hardware() {
        let mut session = Session::new();
        let result = call_tool(&mut session, false, "open_capture",
                               json!({ "path": "can" }));
        let body = body(&result);
        assert_eq!(body["decode"]["protocol"], json!("can"));
        assert_eq!(body["health"]["loaded"], json!(true));
    }

    #[test]
    fn a_script_that_needs_settings_gets_them() {
        let mut session = Session::new();
        // The uart script is 8E1, which no capture can say for itself.
        let body = body(&call_tool(&mut session, false, "open_capture",
                                   json!({ "path": "uart" })));
        assert_eq!(body["decode"]["protocol"], json!("uart"));
        let health = body["health"].clone();
        assert!(health["transactions"].as_u64().unwrap() > 0);
    }

    #[test]
    fn query_and_get_transaction_agree_with_each_other() {
        let mut session = opened();
        let found = body(&call_tool(&mut session, false, "query",
                                    json!({ "expression": "error:any" })));
        assert_eq!(found["matched"], json!(1));
        let id = found["rows"][0]["id"].as_u64().unwrap();

        let detail = body(&call_tool(&mut session, false, "get_transaction",
                                     json!({ "id": id })));
        assert_eq!(detail["row"]["id"], json!(id));
        assert!(detail["explanation"].as_array().unwrap().iter()
            .any(|line| line.as_str().unwrap().contains("nack")));
        assert!(detail["before"].is_object(), "context either side");
    }

    #[test]
    fn a_waveform_can_be_fetched_for_the_transaction_a_query_found() {
        let mut session = opened();
        let found = body(&call_tool(&mut session, false, "query",
                                    json!({ "expression": "error:any" })));
        let start = found["rows"][0]["start_ps"].as_u64().unwrap();
        let end = found["rows"][0]["end_ps"].as_u64().unwrap();

        let wave = body(&call_tool(&mut session, false, "get_waveform",
                                   json!({ "start_ps": start, "end_ps": end })));
        assert_eq!(wave["start_ps"], json!(start));
        let channels = wave["channels"].as_array().unwrap();
        assert_eq!(channels.len(), 2);
        assert!(channels[0]["transitions"].as_array().unwrap().len() > 0);
        assert!(channels[0]["initial"].is_boolean(),
                "the level the range opened at has to be there");
    }

    #[test]
    fn the_analysis_tools_answer_on_an_open_session() {
        let mut session = opened();

        let compared = body(&call_tool(&mut session, false,
                                       "compare_transactions",
                                       json!({ "a": 1, "b": 4 })));
        assert_eq!(compared["comparable"], json!(true));

        let after = body(&call_tool(&mut session, false, "first_error_after",
                                    json!({ "event": "addr:0x3C" })));
        assert_eq!(after["found"], json!(true));

        let summary = body(&call_tool(&mut session, false, "summarize_interval",
                                      json!({ "start_ps": 0,
                                              "end_ps": 200_000_000u64 })));
        assert_eq!(summary["transactions"], json!(6));

        let triggered = body(&call_tool(&mut session, false, "find_trigger",
                                        json!({ "condition":
                                                "addr:0x3C then error:nack" })));
        assert_eq!(triggered["class"], json!("sequence"));
        assert_eq!(triggered["matches"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn a_tool_that_cannot_do_what_was_asked_says_so_as_a_result() {
        let mut session = opened();

        // Not a JSON-RPC error: the transport is fine, the request was not.
        let missing = call_tool(&mut session, false, "get_transaction",
                                json!({ "id": 9999 }));
        assert_eq!(missing["isError"], json!(true));
        assert!(missing["content"][0]["text"].as_str().unwrap()
            .contains("9999"));

        let nonsense = call_tool(&mut session, false, "query",
                                 json!({ "expression": "bus:abc" }));
        assert_eq!(nonsense["isError"], json!(true));

        let unknown = call_tool(&mut session, false, "fly_to_the_moon",
                                json!({}));
        assert_eq!(unknown["isError"], json!(true));
        assert!(unknown["content"][0]["text"].as_str().unwrap()
            .contains("tools/list"));
    }

    #[test]
    fn a_method_this_server_does_not_implement_is_a_jsonrpc_error() {
        let mut session = Session::new();
        let answer = dispatch(&mut session, false, "completion/complete",
                              &json!({}));
        assert!(matches!(answer, Some(Err(_))));
    }

    #[test]
    fn notifications_get_no_answer() {
        let mut session = Session::new();
        assert!(dispatch(&mut session, false, "notifications/initialized",
                         &json!({})).is_none());
    }

    #[test]
    fn resources_and_prompts_are_empty_rather_than_errors() {
        let mut session = Session::new();
        let resources = ask(&mut session, false, "resources/list", json!({}));
        assert_eq!(resources["resources"], json!([]));
        let prompts = ask(&mut session, false, "prompts/list", json!({}));
        assert_eq!(prompts["prompts"], json!([]));
    }

    #[test]
    fn an_evidence_package_can_be_exported_through_a_tool() {
        let mut session = opened();
        let dir = std::env::temp_dir().join("sniffer-mcp-evidence");
        let _ = std::fs::remove_dir_all(&dir);
        let result = call_tool(&mut session, false, "export",
                               json!({ "format": "evidence",
                                       "query": "error:any",
                                       "out": dir.display().to_string() }));
        assert_eq!(result["isError"], json!(false));
        assert!(dir.join("evidence.json").exists());
        assert!(dir.join("evidence.cap").exists());
    }
}
