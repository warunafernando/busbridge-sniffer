"""PHY registers: what an MDIO access was actually asking.

Section 8.1's second example - "MDIO C45 read -> PHY register database ->
symbolic register and decoded bits". An MDIO frame decodes to "phy 1, reg 1,
data 0x796D", which is correct and tells you nothing. The same frame through
here is BMSR with link up, autonegotiation complete, and the abilities the
link partner advertised.

The register set is IEEE 802.3 clause 22's, which every PHY implements at the
same addresses, plus the clause 45 device numbering. Vendor-specific registers
above 0x0F are named as such rather than guessed at - a wrong register name is
worse than an honest "vendor specific".

# Reading a status register is not the same as reading a bit

BMSR's link bit is latching-low: it reads as down if the link has been down
since the last read, not necessarily now. That is the sort of thing that costs
an afternoon, so it is in the output rather than in a comment.
"""

import json
import sys

CLAUSE22 = {
    0x00: "BMCR, basic mode control",
    0x01: "BMSR, basic mode status",
    0x02: "PHYIDR1, identifier high",
    0x03: "PHYIDR2, identifier low",
    0x04: "ANAR, autonegotiation advertisement",
    0x05: "ANLPAR, link partner ability",
    0x06: "ANER, autonegotiation expansion",
    0x07: "ANNPTR, next page transmit",
    0x08: "ANLPNP, link partner next page",
    0x09: "GBCR, 1000BASE-T control",
    0x0A: "GBSR, 1000BASE-T status",
    0x0D: "MACR, MMD access control",
    0x0E: "MAADR, MMD access address or data",
    0x0F: "GBESR, extended status",
}

# Clause 45 device addresses.
DEVICES = {
    1: "PMA/PMD",
    2: "WIS",
    3: "PCS",
    4: "PHY XS",
    5: "DTE XS",
    7: "auto-negotiation",
    30: "vendor specific 1",
    31: "vendor specific 2",
}

BMCR_BITS = [
    (15, "reset"),
    (14, "loopback"),
    (13, "speed select LSB"),
    (12, "autonegotiation enable"),
    (11, "power down"),
    (10, "isolate"),
    (9, "restart autonegotiation"),
    (8, "full duplex"),
    (6, "speed select MSB"),
]

BMSR_BITS = [
    (15, "100BASE-T4 able"),
    (14, "100BASE-X full duplex able"),
    (13, "100BASE-X half duplex able"),
    (12, "10 Mb/s full duplex able"),
    (11, "10 Mb/s half duplex able"),
    (8, "extended status"),
    (6, "MF preamble suppression"),
    (5, "autonegotiation complete"),
    (4, "remote fault"),
    (3, "autonegotiation able"),
    (2, "link up"),
    (1, "jabber detected"),
    (0, "extended capability"),
]


def emit(message):
    print(json.dumps(message))


def fields_of(transaction):
    out = {}
    for f in transaction["fields"]:
        out[f["name"]] = f
    return out


def bits_set(value, table):
    return [name for bit, name in table if value & (1 << bit)]


def main():
    hello = json.loads(sys.stdin.readline())
    if hello.get("hello") != 1:
        emit({"note": "unknown host protocol version; refusing to guess"})
        return

    for line in sys.stdin:
        message = json.loads(line)
        if "end" in message:
            break
        t = message.get("transaction")
        if t is None:
            continue

        fields = fields_of(t)
        register = fields.get("reg")
        if register is None or register.get("value") is None:
            continue

        tid = t["id"]
        reg = int(register["value"])
        derived = []

        device = fields.get("dev")
        if device is not None and device.get("value") is not None:
            number = int(device["value"])
            derived.append({
                "name": "phy.device",
                "display": DEVICES.get(number, "unknown device %d" % number),
                "value": number})
            # In clause 45 the register number is 16 bits and belongs to the
            # device, so clause 22's names do not apply to it.
            emit({"id": tid, "fields": derived})
            continue

        name = CLAUSE22.get(reg)
        if name is None:
            emit({"id": tid, "fields": [
                {"name": "phy.register",
                 "display": "vendor specific 0x%02X" % reg, "value": reg}]})
            continue

        derived.append({"name": "phy.register", "display": name, "value": reg})
        emit({"id": tid, "fields": derived, "label": name.split(",")[0]})

        data = fields.get("data")
        if data is None or data.get("value") is None:
            continue
        value = int(data["value"]) & 0xFFFF

        if reg == 0x00:
            set_bits = bits_set(value, BMCR_BITS)
            speed = "1000 Mb/s" if value & (1 << 6) else (
                "100 Mb/s" if value & (1 << 13) else "10 Mb/s")
            emit({"id": tid, "fields": [
                {"name": "phy.speed", "display": speed},
                {"name": "phy.duplex",
                 "display": "full" if value & (1 << 8) else "half"},
                {"name": "phy.control",
                 "display": ", ".join(set_bits) if set_bits else "nothing set"}]})
            if value & (1 << 11):
                emit({"id": tid, "warning": "the PHY is being told to power down"})
            if value & (1 << 10):
                emit({"id": tid, "warning":
                      "isolate is set, so the PHY will not pass traffic"})
        elif reg == 0x01:
            set_bits = bits_set(value, BMSR_BITS)
            emit({"id": tid, "fields": [
                {"name": "phy.link",
                 "display": "up" if value & (1 << 2) else "down"},
                {"name": "phy.autoneg",
                 "display": "complete" if value & (1 << 5) else "not complete"},
                {"name": "phy.status",
                 "display": ", ".join(set_bits) if set_bits else "nothing set"},
                {"name": "phy.note",
                 "display": "the link bit is latching low, so a down reading "
                            "means it has been down since the last read"}]})
            if value & (1 << 4):
                emit({"id": tid, "warning": "the PHY reports a remote fault"})
            if not value & (1 << 2):
                emit({"id": tid, "warning": "no link", "severity": "notice"})
        elif reg in (0x04, 0x05):
            abilities = []
            for bit, what in [(5, "10BASE-T"), (6, "10BASE-T full duplex"),
                              (7, "100BASE-TX"), (8, "100BASE-TX full duplex"),
                              (9, "100BASE-T4"), (10, "pause"),
                              (11, "asymmetric pause")]:
                if value & (1 << bit):
                    abilities.append(what)
            whose = "advertised" if reg == 0x04 else "link partner"
            emit({"id": tid, "fields": [
                {"name": "phy.abilities",
                 "display": whose + ": "
                            + (", ".join(abilities) if abilities else "none")}]})

    sys.stdout.flush()


if __name__ == "__main__":
    main()
