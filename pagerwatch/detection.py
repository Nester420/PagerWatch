# SPDX-License-Identifier: GPL-3.0-or-later
"""Evidence-based classification. Scores are rule ranks, not probabilities."""
from dataclasses import dataclass, field, asdict
import json
import re
import time


def normalize_mac(value):
    """Canonicalize complete MAC addresses; reject malformed or partial values."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    if re.fullmatch(r"[0-9a-fA-F]{12}", value):
        compact = value
    elif re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", value):
        compact = value.replace(":", "")
    elif re.fullmatch(r"[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}", value):
        compact = value.replace("-", "")
    elif re.fullmatch(r"[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}", value):
        compact = value.replace(".", "")
    else:
        return ""
    return ":".join(compact[i:i+2] for i in range(0, 12, 2)).upper()


def apple_findmy_kind(obs):
    """Decode complete Apple type-0x12 records, including short owner-nearby forms.

    Advertising signatures are spoofable; an AirTag-compatible status is a clue.
    """
    try:
        payload = bytes.fromhex(obs.manufacturer.get("76", ""))
    except (TypeError, ValueError):
        return ""
    pos = 0
    while pos + 2 <= len(payload):
        kind, size = payload[pos:pos+2]
        end = pos + 2 + size
        if end > len(payload):
            return ""
        if kind == 0x12 and size in (2, 25):
            return "airtag" if payload[pos+2] & 0x30 == 0x10 else "findmy"
        pos = end
    return ""


def uuid128(value):
    value = value.lower().removeprefix("0x")
    if len(value) == 4:
        return "0000" + value + "-0000-1000-8000-00805f9b34fb"
    return value


@dataclass
class Observation:
    protocol: str
    address: str
    name: str = ""
    rssi: object = None
    timestamp: float = field(default_factory=time.time)
    frame: str = "advertisement"
    frequency: object = None
    address_type: str = "unknown"
    uuids: list = field(default_factory=list)
    manufacturer: dict = field(default_factory=dict)  # decimal company ID -> hex bytes
    service_data: dict = field(default_factory=dict)  # canonical UUID -> hex bytes

    metadata_source: str = "advertisement"
    security: dict = field(default_factory=dict)
    ssid_status: str = ""
    metadata_seen: dict = field(default_factory=dict)  # receive times for merged BLE fields
    probe_ssid_status: str = ""  # wildcard/directed/missing/incomplete/invalid; no requested SSID retained

    def to_dict(self):
        return asdict(self)


@dataclass
class Hit:
    rule: str
    label: str
    category: str
    score: int
    evidence: str
    source: str

    @property
    def tier(self):
        return "STRONG" if self.score >= 80 else "HINT" if self.score >= 50 else "WEAK"


class Detector:
    def __init__(self, path):
        from pathlib import Path
        self.path = Path(path)
        import hashlib
        raw = self.path.read_bytes()
        self.rules_sha256 = hashlib.sha256(raw).hexdigest()
        document = json.loads(raw)
        self.version = document["version"]
        self.rules = document["rules"]
        self.rule_index = {rule["id"]: rule for rule in self.rules}
        for rule in self.rules:
            if not 0 <= rule["score"] <= 100 or not rule["conditions"]:
                raise ValueError("Invalid rule: " + rule["id"])
            for condition in rule["conditions"]:
                if condition["op"] == "regex":
                    re.compile(condition["value"], re.I)

    def classify(self, obs):
        hits = []
        for rule in self.rules:
            if obs.protocol not in rule["protocols"]:
                continue
            if all(self.matches(obs, c) for c in rule["conditions"]):
                hits.append(Hit(rule["id"], rule["label"], rule["category"],
                                rule["score"], rule["evidence"], rule["source"]))
        # No score fusion: correlated rules must not manufacture certainty.
        return sorted(hits, key=lambda hit: (-hit.score, hit.rule))

    @staticmethod
    def matches(obs, condition):
        key, op, expected = condition["field"], condition["op"], condition["value"]
        if key == "apple_findmy_kind":
            return apple_findmy_kind(obs) == expected
        if key == "company":
            return str(int(expected, 0)) in obs.manufacturer
        if key == "uuid":
            return uuid128(expected) in {uuid128(u) for u in obs.uuids + list(obs.service_data)}
        if key == "payload":
            values = list(obs.manufacturer.values()) + list(obs.service_data.values())
            needle = bytes.fromhex(expected)
            for value in values:
                try:
                    if needle in bytes.fromhex(value):
                        return True
                except ValueError:
                    continue
            return False
        if key.startswith("company_payload:"):
            value = obs.manufacturer.get(str(int(key.split(":", 1)[1], 0)), "")
        elif key.startswith("service_payload:"):
            value = obs.service_data.get(uuid128(key.split(":", 1)[1]), "")
        else:
            value = str(getattr(obs, key, ""))
        if key == "address" and op in ("prefix", "equal", "regex"):
            value = normalize_mac(value)
            if not value:
                return False
        if op == "regex":
            return re.search(expected, value, re.I) is not None
        if op == "prefix":
            return value.lower().startswith(expected.lower())
        if op == "equal":
            return value.lower() == expected.lower()
        if op == "hex_prefix":
            return value.lower().startswith(expected.lower())
        raise ValueError("Unknown operator: " + op)
