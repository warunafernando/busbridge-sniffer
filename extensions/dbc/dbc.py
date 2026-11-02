"""DBC: CAN frames as named signals in engineering units.

Section 8.1's third example - "CAN frame -> DBC analyzer -> named signals and
engineering units". A frame decodes to `0x123 DATA DE AD BE EF`, which is the
truth and not the answer to anybody's question. Through a signal database the
same frame is EngineSpeed 3567.25 rpm and CoolantTemp 51 C.

# The database

`signals.json` beside this script, in the shape a DBC file describes but
without the DBC parser: message id, then each signal's start bit, length,
byte order, signedness, scale, offset and unit. A real deployment points this
at a converted DBC; the format is deliberately the same fields so that
conversion is mechanical.

The bit numbering is the one CAN databases use, which is worth stating because
getting it wrong produces plausible nonsense: bit 0 is the least significant
bit of byte 0, and a big-endian ("Motorola") signal counts its start bit from
the most significant end. Both are implemented here and both are tested by the
sniffer's own suite through the golden capture.

# What it refuses to do

A frame whose id is not in the database gets nothing - not a guess at a layout,
not a partial decode. A frame shorter than its message expects is reported as
such rather than read past its end.
"""

import json
import os
import sys


def emit(message):
    print(json.dumps(message))


def load_database(path):
    if not os.path.exists(path):
        emit({"note": "no signals.json beside the extension, so nothing to "
                      "decode against"})
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    # Keys are hex strings in the file, for the same reason CAN ids are always
    # written in hex.
    out = {}
    for key, message in raw.get("messages", {}).items():
        out[int(str(key), 0)] = message
    return out


def bit_of(data, index):
    """Bit `index` of the payload, little-endian numbering.

    Bit 0 is the least significant bit of byte 0 - the numbering CAN databases
    use.
    """
    byte = index // 8
    if byte >= len(data):
        return None
    return (data[byte] >> (index % 8)) & 1


def extract(data, start, length, big_endian):
    """The raw value of a signal, or None if the payload is too short."""
    value = 0
    if big_endian:
        # Motorola: the start bit is the most significant bit of the signal,
        # and the bits run towards lower bit numbers within each byte, moving
        # to the next byte when one is exhausted.
        bit = start
        for _ in range(length):
            got = bit_of(data, bit)
            if got is None:
                return None
            value = (value << 1) | got
            if bit % 8 == 0:
                bit += 15          # to the top of the next byte
            else:
                bit -= 1
    else:
        for n in range(length):
            got = bit_of(data, start + n)
            if got is None:
                return None
            value |= got << n
    return value


def as_signed(value, length):
    if value & (1 << (length - 1)):
        return value - (1 << length)
    return value


def main():
    hello = json.loads(sys.stdin.readline())
    if hello.get("hello") != 1:
        emit({"note": "unknown host protocol version; refusing to guess"})
        return

    here = os.path.dirname(os.path.abspath(__file__))
    database = load_database(
        hello.get("settings", {}).get("database")
        or os.path.join(here, "signals.json"))

    for line in sys.stdin:
        message = json.loads(line)
        if "end" in message:
            break
        t = message.get("transaction")
        if t is None:
            continue

        fields = {f["name"]: f for f in t["fields"]}
        identifier = fields.get("id")
        if identifier is None or identifier.get("value") is None:
            continue

        tid = t["id"]
        can_id = int(identifier["value"])
        definition = database.get(can_id)
        if definition is None:
            # Named, not decoded: knowing the id is unknown to the database is
            # itself useful, and it is all that can honestly be said.
            emit({"id": tid, "fields": [
                {"name": "dbc.message", "display": "not in the database"}]})
            continue

        data = []
        for f in t["fields"]:
            if f.get("kind") == "data" and f.get("value") is not None:
                data.append(int(f["value"]))

        emit({"id": tid, "label": definition.get("name", "message"),
              "fields": [{"name": "dbc.message",
                          "display": definition.get("name", "message")}]})

        # A remote frame asks for the message; it does not carry it. Decoding
        # signals out of its (absent) payload produced three warnings per
        # frame about data that was never supposed to be there.
        if fields.get("rtr", {}).get("value") == 1 or t.get("kind") == "REMOTE":
            emit({"id": tid, "fields": [
                {"name": "dbc.request",
                 "display": "asking for " + definition.get("name", "it")}]})
            continue

        expected = definition.get("length")
        if expected is not None and len(data) < expected:
            emit({"id": tid, "warning":
                  "%s expects %d payload byte(s) and this frame carries %d"
                  % (definition.get("name", "the message"), expected,
                     len(data))})

        for signal in definition.get("signals", []):
            raw = extract(data, signal["start"], signal["length"],
                          signal.get("big_endian", False))
            if raw is None:
                emit({"id": tid, "warning":
                      "%s runs past the end of this frame's payload"
                      % signal["name"]})
                continue
            if signal.get("signed"):
                raw = as_signed(raw, signal["length"])
            value = raw * signal.get("scale", 1) + signal.get("offset", 0)

            unit = signal.get("unit", "")
            shown = ("%g %s" % (value, unit)).strip()
            derived = {"name": "dbc." + signal["name"], "display": shown}
            if float(value).is_integer():
                derived["value"] = int(value)
            emit({"id": tid, "fields": [derived]})

            low = signal.get("min")
            high = signal.get("max")
            if low is not None and value < low:
                emit({"id": tid, "warning":
                      "%s is %g %s, below its stated minimum of %g"
                      % (signal["name"], value, unit, low)})
            if high is not None and value > high:
                emit({"id": tid, "warning":
                      "%s is %g %s, above its stated maximum of %g"
                      % (signal["name"], value, unit, high)})

    sys.stdout.flush()


if __name__ == "__main__":
    main()
