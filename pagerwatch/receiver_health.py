# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded receive health. Monotonic ages, no radio resets or network activity."""
from collections import deque, OrderedDict
import json
import threading
import time
from .detection import normalize_mac

class ReceiveHealth:
    def __init__(self):
        self.lock = threading.Lock()
        self.events = {}
        self.samples = deque()
        self.sample_bytes = 0
        self.sample_fingerprints=OrderedDict()

    def mark(self, kind, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            row = self.events.setdefault(kind, {'last':now, 'total':0, 'buckets':deque(maxlen=31)})
            row['last'] = now; row['total'] += 1
            second = int(now)
            if row['buckets'] and row['buckets'][-1][0] == second:
                row['buckets'][-1][1] += 1
            else:
                row['buckets'].append([second,1])

    def snapshot(self, now=None):
        now = time.monotonic() if now is None else now
        with self.lock:
            return {kind:{'age_seconds':round(max(0,now-row['last']),1), 'total':row['total'],
                          'recent_30s':sum(n for stamp,n in row['buckets'] if 0 <= now-stamp < 30)}
                    for kind,row in self.events.items()}

    def sample(self, obs, config):
        address = normalize_mac(obs.address)
        excluded = {str(x).strip().upper() for x in config.get('exclude_addresses',[])}
        if not address or address in excluded or obs.protocol.upper()+':'+address in excluded:
            return
        if any(normalize_mac(x) == address for x in excluded if ':' not in x or len(x)==17):
            return
        fingerprint=(obs.name,tuple(obs.uuids),tuple(sorted(obs.manufacturer.items())),tuple(sorted(obs.service_data.items())),
                     getattr(obs,'advertising_data_hex',''))
        key=(address,obs.metadata_source);now=time.monotonic()
        with self.lock:
            previous=self.sample_fingerprints.get(key)
            if previous and previous[1]==fingerprint and now-previous[0]<5:return
            self.sample_fingerprints[key]=(now,fingerprint)
            self.sample_fingerprints.move_to_end(key)
            while len(self.sample_fingerprints)>64:self.sample_fingerprints.popitem(last=False)
        row = {'time':obs.timestamp,'protocol':obs.protocol,'address':address,
               'source':obs.metadata_source,'address_type':obs.address_type,'rssi':obs.rssi,
               'name':obs.name[:128],'uuids':obs.uuids[:32],
               'manufacturer':{str(k)[:64]:str(v)[:3300] for k,v in list(obs.manufacturer.items())[:16]},
               'service_data':{str(k)[:64]:str(v)[:3300] for k,v in list(obs.service_data.items())[:16]},
               'advertising_data_hex':getattr(obs,'advertising_data_hex','')[:3300]}
        encoded = json.dumps(row,separators=(',',':'))
        if len(encoded)>8192:
            return
        with self.lock:
            # One latest sample per address/source; repeated frames do not evict every target.
            for old in list(self.samples):
                if old[0]['address']==address and old[0]['source']==row['source']:
                    self.samples.remove(old); self.sample_bytes -= old[1]; break
            self.samples.append((row,len(encoded))); self.sample_bytes += len(encoded)
            while len(self.samples)>64 or self.sample_bytes>131072:
                self.sample_bytes -= self.samples.popleft()[1]

    def sample_snapshot(self):
        with self.lock:
            return json.loads(json.dumps([row for row,size in self.samples]))

class MetadataWatchdog:
    def __init__(self, started=None):
        self.started = time.monotonic() if started is None else started
        self.last_report = None
        self.names = deque(maxlen=64)

    def report(self, now):
        self.last_report = now
        self.names.clear()

    def name(self, now):
        self.names.append(now)

    def stalled(self, now):
        reference = self.started if self.last_report is None else self.last_report
        grace = 15 if self.last_report is None else 30
        # Continuing name reception distinguishes a broken metadata path from quiet RF.
        return (now-reference > grace and bool(self.names) and now-self.names[-1] <= 5
                and sum(t >= reference for t in self.names) >= 3)
