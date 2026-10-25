# SPDX-License-Identifier: GPL-3.0-or-later
"""MAC-vendor lookup, isolated from camera/device classification.

The compact index stays in about 0.5 MB of RAM; names are read on demand.
Ambiguous flattened prefixes never resolve to an arbitrarily selected vendor.
"""
from collections import OrderedDict, defaultdict
from pathlib import Path
import json
import re
import struct
import threading
from .detection import normalize_mac

MAGIC = b"PWOUI01\x00"
HEADER = struct.Struct("<8sI")
RECORD = struct.Struct("<IIHBx")  # 24-bit prefix, absolute text offset, length, flags


def build_index(source, destination):
    vendors = defaultdict(set)
    rows = 0
    with Path(source).open(encoding="utf-8") as stream:
        for line in stream:
            if line.startswith("#") or "\t" not in line:
                continue
            prefix, name = line.rstrip("\r\n").split("\t", 1)
            prefix, name = prefix.strip().upper(), name.strip()
            if not re.fullmatch(r"[0-9A-F]{6}", prefix) or not name:
                continue
            vendors[int(prefix, 16)].add(name)
            rows += 1
    keys = sorted(vendors)
    offset = HEADER.size + RECORD.size * len(keys)
    records, labels = [], []
    ambiguous = 0
    for key in keys:
        names = vendors[key]
        multiple = len(names) != 1
        if multiple:
            ambiguous += 1
            label = "Ambiguous prefix (%d listed names)" % len(names)
        else:
            label = next(iter(names))
        text = label.encode("utf-8")
        if len(text) > 65535:
            raise ValueError("Vendor name too long")
        records.append(RECORD.pack(key, offset, len(text), int(multiple)))
        labels.append(text)
        offset += len(text)
    with Path(destination).open("wb") as stream:
        stream.write(HEADER.pack(MAGIC, len(keys)))
        stream.write(b"".join(records))
        stream.write(b"".join(labels))
    return {"valid_rows": rows, "distinct_prefixes": len(keys), "ambiguous_prefixes": ambiguous}


class VendorLookup:
    def __init__(self, path, cache_size=1024):
        self.lock=threading.RLock()
        self.file = Path(path).open("rb")
        try:
            header = self.file.read(HEADER.size)
            if len(header) != HEADER.size:
                raise ValueError("Truncated OUI index")
            magic, self.count = HEADER.unpack(header)
            if magic != MAGIC or self.count > 1000000:
                raise ValueError("Invalid OUI index header")
            self.index = self.file.read(RECORD.size * self.count)
            if len(self.index) != RECORD.size * self.count:
                raise ValueError("Truncated OUI records")
            self.size = self.file.seek(0, 2)
        except Exception:
            self.file.close()
            raise
        self.cache = OrderedDict()
        self.cache_size = cache_size

    def close(self):
        with self.lock:self.file.close()

    def find_prefix(self,key):
        with self.lock:return self._find_prefix(key)

    def _find_prefix(self, key):
        if key in self.cache:
            self.cache.move_to_end(key)
            return dict(self.cache[key])
        low, high = 0, self.count
        result = {"name": "", "status": "not_found", "prefix": "%06X" % key}
        while low < high:
            middle = (low + high) // 2
            prefix, offset, length, flags = RECORD.unpack_from(self.index, middle * RECORD.size)
            if prefix < key:
                low = middle + 1
            elif prefix > key:
                high = middle
            else:
                if offset < HEADER.size + len(self.index) or offset + length > self.size:
                    raise ValueError("Invalid OUI name offset")
                self.file.seek(offset)
                result = {"name": self.file.read(length).decode("utf-8", "replace"),
                          "status": "ambiguous" if flags & 1 else "vendor_only", "prefix": "%06X" % key}
                break
        if len(self.cache) >= self.cache_size:
            self.cache.popitem(last=False)
        self.cache[key] = dict(result)
        return result

    def lookup(self, obs):
        empty = {"name": "", "status": "invalid_address", "prefix": ""}
        address = normalize_mac(obs.address)
        if not address:
            return empty
        if obs.protocol == "ble" and obs.address_type != "public":
            empty["status"] = "ble_random_or_unknown"
            return empty
        first = int(address[:2], 16)
        if first & 1:
            empty["status"] = "multicast_address"
            return empty
        if first & 2:
            empty["status"] = "locally_administered_address"
            return empty
        return self.find_prefix(int(address.replace(":", "")[:6], 16))
