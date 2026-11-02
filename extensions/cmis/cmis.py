"""CMIS: what an I2C transfer to an optical module means.

Section 8.1's first example - "I2C transfer -> CMIS page/register analyzer ->
field name + semantic value". A transceiver answers at 0x50 and presents a
paged register map: the lower page (bytes 0x00 to 0x7F) is always there, the
upper page depends on what was last written to byte 0x7F, and the numbers in
it are fixed-point temperatures, voltages and optical powers rather than bytes.

That last part is the point of a device analyser. `0x1A 0x31` in a decode is
correct and useless; 26.191 C is the same two bytes with the module's own
meaning attached.

# Why this keeps state between transactions

Reading a CMIS register is two bus transactions: a write of the register
address, then a read of its contents. So the read on its own says nothing -
the register it answers was named by the transaction before it. The analyser
therefore remembers, per module address, which register was last selected, and
which page was last written to 0x7F.

That is what a device analyser is for. It is also why the state is per address
and reset by nothing: a capture that begins mid-conversation genuinely does not
know what page the module is on, and this says so rather than assuming zero.

# What it refuses to do

It does not touch the wire, and it cannot: it is handed transactions and can
only add fields. It also does not guess. A read from an upper-page register
with no page select in the capture is reported as being from an unknown page,
because a plausible wrong register name is worse than none.

Written against CMIS 5.0's lower page, with the registers that come up when a
module will not come up.
"""

import json
import sys

# The module's own address. 0x51 is the second, optional one.
MODULE_ADDRESSES = (0x50, 0x51)

PAGE_SELECT = 0x7F

# Lower page: always accessible, whatever page is selected.
LOWER_PAGE = {
    0x00: "identifier",
    0x01: "CMIS revision",
    0x02: "memory model and interrupt flags",
    0x03: "module state and fault flags",
    0x0E: "module temperature",
    0x0F: "module temperature, low byte",
    0x10: "supply voltage",
    0x11: "supply voltage, low byte",
    0x1A: "global controls: low power and software reset",
    0x54: "vendor name",
    0x64: "vendor part number",
    0x74: "vendor serial number",
    0x7F: "page select",
}

IDENTIFIERS = {
    0x03: "SFP or SFP+",
    0x0B: "DSFP",
    0x0D: "QSFP+",
    0x11: "QSFP28",
    0x18: "QSFP-DD",
    0x19: "OSFP",
    0x1E: "QSFP+ with CMIS",
}

MODULE_STATES = {
    0x01: "reset",
    0x02: "low power",
    0x03: "powering up",
    0x04: "ready",
    0x05: "powering down",
    0x06: "fault",
}

# The alarm thresholds a module is usually specified to, for the two monitors
# this decodes. Stated here rather than assumed, because a warning against an
# invented threshold is worse than no warning.
TEMPERATURE_ALARM_C = 75.0
VOLTAGE_RANGE_V = (3.135, 3.465)


def emit(message):
    print(json.dumps(message))


def fields_of(transaction):
    return {f["name"]: f for f in transaction["fields"]}


def payload(transaction):
    out = []
    for f in transaction["fields"]:
        if f.get("kind") == "data" and f.get("value") is not None:
            out.append(int(f["value"]))
    return out


def signed16(msb, lsb):
    """CMIS temperatures are signed 16-bit, 1/256 C per count."""
    raw = (msb << 8) | lsb
    if raw & 0x8000:
        raw -= 0x10000
    return raw


def name_of(register, page):
    """The register's name, and whether the name can be trusted."""
    if register <= 0x7F:
        # The lower page is always mapped, whatever page is selected.
        return LOWER_PAGE.get(register), True
    if page is None:
        return None, False
    return "page 0x%02X register 0x%02X" % (page, register), True


def interpret(register, values):
    """Fields and warnings for a register's contents.

    Returns (fields, label, warnings).
    """
    fields = []
    warnings = []
    label = None

    if register == 0x00 and values:
        kind = IDENTIFIERS.get(values[0], "unknown type 0x%02X" % values[0])
        label = "read identifier: " + kind
        fields.append({"name": "cmis.identifier", "display": kind,
                       "value": values[0]})
    elif register == 0x03 and values:
        state = (values[0] >> 1) & 0x07
        fields.append({"name": "cmis.module_state",
                       "display": MODULE_STATES.get(state,
                                                    "reserved (%d)" % state),
                       "value": state})
        label = "read module state"
        if state == 0x06:
            warnings.append("the module reports a fault")
    elif register == 0x0E and len(values) >= 2:
        celsius = signed16(values[0], values[1]) / 256.0
        label = "read temperature"
        fields.append({"name": "cmis.temperature", "display": "%.3f C" % celsius})
        if celsius > TEMPERATURE_ALARM_C:
            warnings.append("module temperature %.1f C is above the usual "
                            "%.0f C alarm" % (celsius, TEMPERATURE_ALARM_C))
    elif register == 0x10 and len(values) >= 2:
        volts = ((values[0] << 8) | values[1]) * 0.0001
        label = "read supply voltage"
        fields.append({"name": "cmis.voltage", "display": "%.4f V" % volts})
        low, high = VOLTAGE_RANGE_V
        if not low <= volts <= high:
            warnings.append("supply voltage %.4f V is outside the usual "
                            "%.3f to %.3f V" % (volts, low, high))
    return fields, label, warnings


def main():
    hello = json.loads(sys.stdin.readline())
    if hello.get("hello") != 1:
        emit({"note": "unknown host protocol version; refusing to guess"})
        return

    # Per module address: the page last selected, and the register last
    # written, which is what the next read will answer.
    page = {}
    selected = {}

    start_page = hello.get("settings", {}).get("page")
    if start_page not in (None, "", "unknown"):
        try:
            for address in MODULE_ADDRESSES:
                page[address] = int(str(start_page), 0)
        except ValueError:
            emit({"note": "the page setting is not a number; ignoring it"})

    for line in sys.stdin:
        message = json.loads(line)
        if "end" in message:
            break
        t = message.get("transaction")
        if t is None:
            continue

        fields = fields_of(t)
        address_field = fields.get("address")
        if address_field is None or address_field.get("value") is None:
            continue
        address = int(address_field["value"])
        if address not in MODULE_ADDRESSES:
            continue

        tid = t["id"]
        bytes_ = payload(t)
        write = fields.get("direction", {}).get("display") == "W"

        emit({"id": tid, "fields": [
            {"name": "cmis.device",
             "display": "optical module at " + address_field["display"]}]})

        if write:
            if not bytes_:
                emit({"id": tid, "label": "probe for the module"})
                continue

            register = bytes_[0]
            values = bytes_[1:]

            if register == PAGE_SELECT and values:
                page[address] = values[0]
                emit({"id": tid,
                      "label": "select page 0x%02X" % values[0],
                      "fields": [{"name": "cmis.page",
                                  "display": "0x%02X" % values[0],
                                  "value": values[0]}]})
                continue

            # A write of just the register address selects it for the read
            # that follows; a write with data behind it is a real write.
            selected[address] = register
            named, known = name_of(register, page.get(address))
            derived = [{"name": "cmis.register", "display": "0x%02X" % register,
                        "value": register, "kind": "address"}]
            if named:
                derived.append({"name": "cmis.field", "display": named})
            if page.get(address) is not None and register > 0x7F:
                derived.append({"name": "cmis.page",
                                "display": "0x%02X" % page[address],
                                "value": page[address]})
            emit({"id": tid, "fields": derived})

            if not known:
                emit({"id": tid, "warning":
                      "register 0x%02X is in the upper page and no page select "
                      "appears in this capture, so which register this is "
                      "cannot be known" % register})
                continue

            if values:
                extra, label, warnings = interpret(register, values)
                emit({"id": tid,
                      "label": label or ("write " + (named or "0x%02X" % register)),
                      "fields": extra})
                for w in warnings:
                    emit({"id": tid, "warning": w})
            else:
                emit({"id": tid,
                      "label": "select " + (named or "0x%02X" % register)})
            continue

        # A read: the register it answers was named by the write before it.
        register = selected.get(address)
        if register is None:
            emit({"id": tid, "warning":
                  "a read with no register select before it in this capture, "
                  "so what these bytes are cannot be known"})
            continue

        named, known = name_of(register, page.get(address))
        derived = [{"name": "cmis.register", "display": "0x%02X" % register,
                    "value": register, "kind": "address"}]
        if named:
            derived.append({"name": "cmis.field", "display": named})
        emit({"id": tid, "fields": derived})

        if not known:
            emit({"id": tid, "warning":
                  "this answers register 0x%02X in an upper page nobody "
                  "selected in this capture" % register})
            continue

        extra, label, warnings = interpret(register, bytes_)
        emit({"id": tid, "label": label or ("read " + named),
              "fields": extra})
        for w in warnings:
            emit({"id": tid, "warning": w})

    sys.stdout.flush()


if __name__ == "__main__":
    main()
