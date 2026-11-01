# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded parsers for tcpdump PCAP, radiotap and BlueZ text events."""
import re
import struct
import time
from .detection import Observation, uuid128


class PcapReader:
    def __init__(self):
        self.buffer = bytearray()
        self.endian = None
        self.linktype = None
        self.scale = 1e6

    def feed(self, data):
        self.buffer.extend(data)
        out = []
        if self.endian is None:
            if len(self.buffer) < 24:
                return out
            magic = bytes(self.buffer[:4])
            formats = {b"\xd4\xc3\xb2\xa1": ("<", 1e6), b"\xa1\xb2\xc3\xd4": (">", 1e6),
                       b"\x4d\x3c\xb2\xa1": ("<", 1e9), b"\xa1\xb2\x3c\x4d": (">", 1e9)}
            if magic not in formats:
                raise ValueError("Expected classic PCAP from tcpdump")
            self.endian, self.scale = formats[magic]
            self.linktype = struct.unpack_from(self.endian + "I", self.buffer, 20)[0] & 0xffff
            if self.linktype not in (105, 127):
                raise ValueError("Expected 802.11 or radiotap PCAP; link type=" + str(self.linktype))
            del self.buffer[:24]
        while len(self.buffer) >= 16:
            sec, frac, size, original_size = struct.unpack_from(self.endian + "IIII", self.buffer)
            if size > 65536:
                raise ValueError("Oversized PCAP record")
            if len(self.buffer) < 16 + size:
                break
            packet = bytes(self.buffer[16:16 + size])
            del self.buffer[:16 + size]
            obs = parse_wifi(packet, self.linktype, sec + frac / self.scale, truncated=size < original_size)
            if obs:
                out.append(obs)
        return out


def parse_wifi(packet, linktype=127, timestamp=None, truncated=False):
    frequency = rssi = None
    radiotap_flags = 0
    if linktype == 127:
        if len(packet) < 8 or packet[0] != 0:
            return None
        length = struct.unpack_from("<H", packet, 2)[0]
        if not 8 <= length <= len(packet):
            return None
        present = struct.unpack_from("<I", packet, 4)[0]
        pos = 8
        ext = present
        while ext & (1 << 31):
            if pos + 4 > length:
                return None
            ext = struct.unpack_from("<I", packet, pos)[0]
            pos += 4
        # All earlier fields must be skipped at their specified alignments.
        for bit, alignment, size in [(0, 8, 8), (1, 1, 1), (2, 1, 1),
                                     (3, 2, 4), (4, 2, 2), (5, 1, 1)]:
            if not present & (1 << bit):
                continue
            pos = (pos + alignment - 1) // alignment * alignment
            if pos + size > length:
                return None
            if bit == 1:
                radiotap_flags = packet[pos]
            elif bit == 3:
                frequency = struct.unpack_from("<H", packet, pos)[0]
            elif bit == 5:
                rssi = struct.unpack_from("b", packet, pos)[0]
            pos += size
        packet = packet[length:]
        if radiotap_flags & 0x40:  # BADFCS: do not classify corrupted headers/IEs.
            return None
        if radiotap_flags & 0x10 and not truncated:  # Full frame includes its trailing FCS.
            if len(packet) < 4:
                return None
            packet = packet[:-4]
    if len(packet) < 24:
        return None
    fc = struct.unpack_from("<H", packet)[0]
    subtype = (fc >> 4) & 15
    if (fc & 3) or (fc >> 2) & 3 or subtype not in (0, 1, 2, 3, 4, 5, 8, 10, 11, 12, 13, 14):
        return None
    if fc & 0x4000:  # encrypted/malformed management body
        return None
    frame = {0: "association_request", 1: "association_response",
             2: "reassociation_request", 3: "reassociation_response",
             4: "probe_request", 5: "probe_response", 8: "beacon",
             10: "management", 11: "authentication", 12: "management",
             13: "action", 14: "action"}[subtype]
    # Transmitter address; a probe's SSID is a requested network, not its device name.
    address = ":".join("%02X" % b for b in packet[10:16])
    if subtype not in (4, 5, 8):
        # Header-only observation. Never label the recipient as a transmitter,
        # inherit its signal, or interpret management bodies as SSID elements.
        return Observation("wifi", address, "", rssi,
                           timestamp if timestamp is not None else time.time(),
                           frame, frequency, ssid_status="not_advertised")
    offset = 24 if subtype == 4 else 36
    if offset > len(packet):
        return None
    name = ""
    ssid_status="not_advertised" if subtype==4 else "not_captured"
    elements=[];complete=not truncated
    while offset + 2 <= len(packet):
        tag, size = packet[offset:offset + 2]
        offset += 2
        if offset + size > len(packet):
            complete=False
            break
        value = packet[offset:offset + size]
        offset += size
        elements.append((tag,value))
        if tag == 0 and subtype != 4 and size <= 32:
            name = value.decode("utf-8", "replace").replace("\x00", "")
            ssid_status="advertised" if name else "hidden"
    if offset!=len(packet):complete=False
    if not complete and not name and ssid_status!="hidden":ssid_status="incomplete"
    probe_ssid_status = ""
    if subtype == 4:
        ssids = [value for tag, value in elements if tag == 0]
        # Missing, duplicate or truncated IEs are not wildcard evidence.
        if not complete:
            probe_ssid_status = "incomplete"
        elif not ssids:
            probe_ssid_status = "missing"
        elif len(ssids) != 1 or len(ssids[0]) > 32:
            probe_ssid_status = "invalid"
        else:
            probe_ssid_status = "wildcard" if not ssids[0] else "directed"
    security={}
    if subtype in (5,8):
        from .security import advertised_security
        security=advertised_security(struct.unpack_from('<H',packet,34)[0],elements,complete)
    return Observation("wifi", address, name, rssi,
                       timestamp if timestamp is not None else time.time(), frame, frequency,security=security,ssid_status=ssid_status,probe_ssid_status=probe_ssid_status)


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
DEVICE = re.compile(r"\[(NEW|CHG|DEL)\]\s+Device\s+([0-9a-f:]{17})\s*(.*)", re.I)
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


class BluezParser:
    def __init__(self, max_devices=2048, ttl=120):
        self.devices = {}
        self.pending = None
        self.metadata_generation = 0
        self.max_devices = max_devices
        self.ttl = ttl

    def feed(self, raw, now=None):
        now = time.time() if now is None else now
        line = ANSI.sub("", raw).strip()
        match = DEVICE.search(line)
        if not match:
            # BlueZ writes binary property values on indented continuation lines.
            if self.pending:
                mac, field, key = self.pending
                hexline = re.match(r"^((?:[0-9a-fA-F]{2}(?:\s+|$))+)", line)
                if hexline and mac in self.devices:
                    value = "".join(hexline.group(1).split())
                    table = self.devices[mac]["obs"].manufacturer if field == "mfg" else self.devices[mac]["obs"].service_data
                    table[key] = (table.get(key, "") + value)[:1024]
                    self.devices[mac]["updated"] = now
            return
        action, mac, prop = match.groups()
        mac = mac.upper()
        self.pending = None
        if action.upper() == "DEL":
            self.devices.pop(mac, None)
            return
        if mac not in self.devices or now - self.devices[mac]["updated"] > self.ttl:
            if len(self.devices) >= self.max_devices:
                self.devices.pop(min(self.devices, key=lambda k: self.devices[k]["updated"]))
            self.devices[mac] = {"obs": Observation("ble", mac, metadata_source="bluez_properties"), "updated": now,
                                 "keys": {}, "changed": now, "emitted": -1, "radio": 0,
                                 "evidence_times": {}}
        entry = self.devices[mac]
        obs = entry["obs"]
        entry["updated"] = entry["changed"] = now
        if action.upper() == "NEW" and ": " not in prop:
            obs.name = prop
            entry["radio"] = now
            obs.timestamp = now
            return
        key, _, value = prop.partition(": ")
        value = value.strip()
        if key in ("Name", "Alias"):
            obs.name = value
        elif key == "AddressType":
            obs.address_type = value
        elif key == "RSSI":
            number = re.search(r"\((-?\d+)\)", value) or re.match(r"(-?\d+)(?:\s|$)", value)
            if number:
                obs.rssi = int(number.group(1))
                obs.timestamp = entry["radio"] = now
        elif key in ("UUID", "UUIDs"):
            short = re.findall(r"(?i)(?<![0-9a-f])0x([0-9a-f]{4})(?![0-9a-f])", value)
            if short:
                value += " " + " ".join(uuid128(u) for u in short)
            obs.uuids = sorted(set(obs.uuids + [u.lower() for u in UUID.findall(value)]))[:64]
            for value_uuid in UUID.findall(value):
                entry["evidence_times"][("uuid", value_uuid.lower())] = now
            if UUID.findall(value):self.metadata_generation += 1
            obs.timestamp = entry["radio"] = now
        elif key == "ManufacturerData.Key":
            number = re.search(r"0x([0-9a-f]+)", value, re.I)
            if number:
                entry["keys"]["mfg"] = str(int(number.group(1), 16))
        elif key == "ServiceData.Key":
            found = UUID.search(value)
            if found:
                entry["keys"]["svc"] = found.group().lower()
        elif key.rstrip(":") in ("ManufacturerData.Value", "ServiceData.Value"):
            field = "mfg" if key.startswith("Manufacturer") else "svc"
            data_key = entry["keys"].get(field)
            if data_key:
                table = obs.manufacturer if field == "mfg" else obs.service_data
                self.metadata_generation += 1
                table[data_key] = ""
                entry["evidence_times"][(field, data_key)] = now
                self.pending = (mac, field, data_key)
                obs.timestamp = entry["radio"] = now

    def drain(self, now=None):
        now = time.time() if now is None else now
        out = []
        for mac, entry in list(self.devices.items()):
            if now - entry["updated"] > self.ttl:
                del self.devices[mac]
                continue
            for (kind, key), timestamp in list(entry["evidence_times"].items()):
                if now - timestamp > self.ttl:
                    obs = entry["obs"]
                    if kind == "uuid":
                        obs.uuids = [u for u in obs.uuids if u != key]
                    else:
                        (obs.manufacturer if kind == "mfg" else obs.service_data).pop(key, None)
                    del entry["evidence_times"][(kind, key)]
                    entry["changed"] = now
            if entry["changed"] <= entry["emitted"] or now - entry["radio"] > 15:
                continue
            entry["emitted"] = entry["changed"]
            # Copy: later parser events must not mutate queued evidence.
            obs = entry["obs"]
            out.append(Observation(**obs.to_dict()))
            out[-1].uuids = list(obs.uuids)
            out[-1].manufacturer = dict(obs.manufacturer)
            out[-1].service_data = dict(obs.service_data)
            prefixes={'uuid':'uuid','mfg':'company','svc':'service'}
            out[-1].metadata_seen = {prefixes[kind]+':'+str(key):stamp for (kind,key),stamp in entry['evidence_times'].items()}
        return out


def bluez_cached_properties(obs, text):
    """Enrich only a recently observed address, without inventing a new sighting.

    bluetoothctl info reads BlueZ's object cache; it does not connect or pair.
    The explicit metadata_source prevents treating all properties as fresh ads.
    """
    header = re.search(r"(?m)^Device\s+([0-9A-Fa-f:]{17})(?:\s+\((public|random)\))?", text)
    if not header or header.group(1).upper() != obs.address.upper():
        return None
    parser = BluezParser()
    mac = obs.address.upper()
    parser.feed("[NEW] Device " + mac + " Unknown", now=obs.timestamp)
    copy = Observation(**obs.to_dict())
    copy.uuids, copy.manufacturer, copy.service_data = list(obs.uuids), dict(obs.manufacturer), dict(obs.service_data)
    parser.devices[mac]["obs"] = copy
    if header.group(2):
        copy.address_type = header.group(2)
    for raw in text[header.end():].splitlines():
        line = raw.strip()
        if re.match(r"^(?:Name|AddressType|UUIDs?|ManufacturerData\.(?:Key|Value)|ServiceData\.(?:Key|Value)):", line):
            parser.feed("[CHG] Device " + mac + " " + line, now=obs.timestamp)
        elif re.match(r"^(?:[0-9a-fA-F]{2}\s+){1,}", line):
            parser.feed(line, now=obs.timestamp)
        else:
            parser.pending = None
    copy.timestamp = obs.timestamp
    if copy.to_dict() == obs.to_dict():
        return None
    copy.metadata_source = "bluez_cached_properties"
    return copy
