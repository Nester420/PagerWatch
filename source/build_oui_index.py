#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Rebuild the offline vendor index from the attributed source snapshot."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from pagerwatch.vendors import build_index

if __name__ == "__main__":
    source = ROOT / "third_party/wardrive-go/oui_manuf.txt"
    destination = ROOT / "data/oui_lookup.bin"
    destination.parent.mkdir(exist_ok=True)
    print(json.dumps(build_index(source, destination), indent=2))
