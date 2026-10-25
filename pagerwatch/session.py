# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded device history and private, offline session files."""
from collections import OrderedDict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import csv
import json
import os
import time
import uuid
from .detection import Hit, normalize_mac
from .fieldtools import watch_hits, StorageHealth


def device_key(obs):
    return obs.protocol + ":" + (normalize_mac(obs.address) or obs.address.upper())


@dataclass
class Device:
    obs: object
    hits: list
    first_seen: float
    seen: int = 1
    history: object = field(default_factory=lambda: deque(maxlen=30))
    last_alert: float = 0
    alert_score: int = 0
    vendor: dict = field(default_factory=dict)
    bluetooth: dict = field(default_factory=dict)
    ssid_names: dict = field(default_factory=dict)
    ap_name: str = ""
    ap_seen: bool = False
    ssid_status: str = ""
    last_frequency: object = None
    first_location: object = None
    last_location: object = None
    strongest_location: object = None
    evidence_signature: object = None
    base_hits: tuple = ()
    security: dict = field(default_factory=dict)
    security_time: object = None


    def signal_average(self,now=None):
        """Mean of up to five samples from the last ten seconds, after any long gap."""
        now=time.time() if now is None else now
        values=[];last=None
        for stamp,rssi in self.history:
            if not 0<=now-stamp<=10:continue
            if last is not None and stamp-last>10:values=[]
            values.append((stamp,rssi));last=stamp
        values=values[-5:]
        return {'rssi_average':round(sum(v for _,v in values)/len(values),1) if values else None,
                'rssi_samples':len(values),'rssi_average_age':round(now-values[-1][0],1) if values else None}


class Session:
    def __init__(self, root, detector, config):
        self.detector = detector
        self.config = config
        self.devices = OrderedDict()
        self.excluded = {normalize_mac(a) or a.upper() for a in config.get("exclude_addresses", [])}
        self.limit = int(config.get("max_devices", 2000))
        self.alerts = deque(maxlen=100)
        self.last_write = {}
        self.alerted_keys = set()
        self.discovery_keys = set()
        self.discovery_bytes = 0
        self.discovery_error = ""
        self.events = 0
        self.located_events = 0
        self.gps_coverage = dict.fromkeys(("tagged","stale","inaccurate","unavailable"),0)
        self.classifications = 0
        self.evicted = 0
        self.log_error = ""
        self.alert_callback = None
        self.closed = False
        self.tracked_key = None
        self.gps_status = {}
        self.storage_health = StorageHealth()
        self.storage = {}
        self.reliability={};self.preflight=[];self.checkpoint_error="";self.checkpoint_at=None;self.next_checkpoint=0;self.checkpoint_generation=0
        self.vendors = None
        self.bluetooth_labels = None
        self.bluetooth_status = "BLE lookup unavailable"
        self.vendor_status = "OUI lookup unavailable"
        self.started = time.time()
        self.started_mono=time.monotonic();self.ended_mono=None
        self.bytes_written = 0
        self.log_limit = int(config.get("max_log_mb", 20)) * 1024 * 1024
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.path = Path(root) / (stamp + "-" + uuid.uuid4().hex[:8])
        self.path.mkdir(parents=True, mode=0o700)
        self.stream = (self.path / "observations.jsonl").open("x", encoding="utf-8")
        os.chmod(self.path / "observations.jsonl", 0o600)
        self.discoveries = (self.path / "discoveries.jsonl").open("xb")
        os.chmod(self.path / "discoveries.jsonl", 0o600)

    def ingest(self, obs, gps=None, gps_reason=None):
        obs.address = normalize_mac(obs.address) or obs.address.upper()
        key = device_key(obs)
        if obs.address in self.excluded or key.upper() in self.excluded:
            return
        device = self.devices.get(key)
        signature = (obs.protocol, obs.address, obs.name, obs.frame, obs.address_type,
                     tuple(obs.uuids), tuple(sorted(obs.manufacturer.items())),
                     tuple(sorted(obs.service_data.items())), obs.metadata_source, obs.probe_ssid_status)
        changed = device is None or signature != device.evidence_signature
        if changed:
            hits = self.detector.classify(obs)
            self.classifications += 1
        else:
            hits = list(device.base_hits)
        if device is None:
            if len(self.devices) >= self.limit:
                old_key, _ = self.devices.popitem(last=False)
                self.last_write.pop(old_key, None)
                self.evicted += 1
            device = Device(obs, hits, obs.timestamp)
            self.devices[key] = device
        else:
            device.obs = obs
            device.hits = hits
            device.seen += 1
            self.devices.move_to_end(key)
        if obs.frequency is not None:
            device.last_frequency = obs.frequency
        device.evidence_signature = signature
        device.base_hits = tuple(hits)
        if gps:
            location = dict(gps, observed_at=obs.timestamp, rssi=obs.rssi,
                            frequency=obs.frequency, name=obs.name or device.ap_name)
            if device.first_location is None:
                device.first_location = location
            device.last_location = location
            previous = device.strongest_location
            if previous is None or (obs.rssi is not None and (previous.get("rssi") is None or obs.rssi > previous["rssi"])):
                device.strongest_location = location
            self.located_events += 1
        if obs.protocol == "wifi" and obs.frame in ("beacon", "probe_response", "scan_result"):
            device.ap_seen=True;device.ssid_status=obs.ssid_status or ("advertised" if obs.name else "not_captured")
            device.ssid_names = {name: stamp for name,stamp in device.ssid_names.items() if 0 <= obs.timestamp-stamp <= 120}
            if obs.name:
                device.ap_name = obs.name
                device.ssid_names[obs.name] = obs.timestamp
                if len(device.ssid_names)>32:
                    oldest = min(device.ssid_names,key=device.ssid_names.get)
                    del device.ssid_names[oldest]
            if len(device.ssid_names)>=5:
                hits.append(Hit("ssid-name-pool", "Multiple SSIDs from one BSSID", "RF OBSERVATION", 55,
                    "%d nonempty SSIDs observed from this BSSID within 120s. May reflect a lab, reconfiguration or spoofing; not proof of an attack." % len(device.ssid_names),
                    "https://github.com/hak5/wifipineapplepager-payloads/blob/5ed2f6c307880c9201c0f7912da6076caa5cc1d7/library/user/reconnaissance/find_hackers/payload.sh"))
                hits.sort(key=lambda hit:(-hit.score,hit.rule))
            device.hits = hits
        if self.vendors and changed:
            device.vendor = self.vendors.lookup(obs)
        if self.bluetooth_labels and changed:
            device.bluetooth = self.bluetooth_labels.lookup(obs)
        if obs.security and obs.frame in ('beacon','probe_response','scan_result'):
            device.security=dict(obs.security);device.security_time=obs.timestamp
        hits=sorted(hits+watch_hits(self.config,obs),key=lambda hit:(-hit.score,hit.rule))
        device.hits=hits
        if obs.rssi is not None:
            device.history.append((obs.timestamp, obs.rssi))
        self.events += 1
        reason="tagged" if gps else gps_reason if gps_reason in ("stale","inaccurate") else "unavailable"
        self.gps_coverage[reason]+=1
        score = hits[0].score if hits else 0
        notify = score >= self.config.get("alert_threshold", 75) and key not in self.alerted_keys
        if gps and key not in self.discovery_keys and not self.discovery_error:
            # First accepted GPS sighting stays anchored for the entire session,
            # even when the live inventory evicts this address. No browser needed.
            point = {"key": key, "protocol": obs.protocol, "address": obs.address,
                     "name": obs.name or device.ap_name, "network_name": device.ap_name,
                     "lat": gps["lat"], "lon": gps["lon"], "accuracy_m": gps.get("accuracy_m"),
                     "time": obs.timestamp, "rssi": obs.rssi, "frequency": obs.frequency,
                     "matched": bool(hits), "label": hits[0].label if hits else "",
                     "position_kind": "observer", "location_source": gps.get("source", "gpsd")}
            line = (json.dumps(point, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
            if self.discovery_bytes + len(line) > self.log_limit:
                self.discovery_error = "First GPS sighting log limit reached; finish and start a new session"
            else:
                try:
                    self.discoveries.write(line)
                    self.discoveries.flush()
                    self.discovery_bytes += len(line)
                    self.discovery_keys.add(key)
                except OSError as exc:
                    self.discovery_error = "First GPS sighting write failed: " + str(exc)
        if notify:
            self.alerted_keys.add(key)
            device.last_alert = obs.timestamp
            device.alert_score = score
            self.alerts.appendleft({"key": key, "time": obs.timestamp, "label": hits[0].label,
                                    "tier": hits[0].tier, "score": score})
            if self.alert_callback:
                self.alert_callback(device)
        if notify or obs.timestamp - self.last_write.get(key, 0) >= 5:
            record = {"observation": obs.to_dict(), "matches": [asdict(hit) for hit in hits],
                      "local_note": self.config.get("device_notes",{}).get(key,{}), "security": device.security,
                      "observer_location": gps, "network_name": device.ap_name, "mac_vendor": device.vendor, "bluetooth_context": device.bluetooth, "observed_ssids": device.ssid_names}
            line = json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"
            size = len(line.encode("utf-8"))
            if self.bytes_written + size > self.log_limit:
                self.log_error = "Session log limit reached; finish and start a new session"
            elif not self.log_error:
                try:
                    self.stream.write(line)
                    self.stream.flush()
                    self.bytes_written += size
                except OSError as exc:
                    self.log_error = "Log write failed: " + str(exc)
            self.last_write[key] = obs.timestamp

    def live(self, now=None):
        now = time.time() if now is None else now
        return [d for d in self.devices.values() if 0 <= now - d.obs.timestamp < 30]

    def visible(self, matched=False, protocol=None):
        values = list(self.devices.values())
        if protocol:
            values = [d for d in values if d.obs.protocol == protocol]
        if matched:
            values = [d for d in values if d.hits]
            values.sort(key=lambda d: (-d.hits[0].score, -d.obs.timestamp))
        else:
            values.sort(key=lambda d: -d.obs.timestamp)
        return values

    def exclude(self, obs):
        key = device_key(obs)
        self.excluded.add(key.upper())
        self.devices.pop(key, None)
        self.last_write.pop(key, None)
        self.alerts = deque((a for a in self.alerts if a["key"] != key), maxlen=100)
        self.config["exclude_addresses"] = sorted(self.excluded)

    def field_summary(self):
        elapsed=(self.ended_mono if self.ended_mono is not None else time.monotonic())-self.started_mono
        return {'duration_seconds':round(max(0,elapsed),1),'observations':self.events,
                'geotagged_observations':self.located_events,'gps_reasons':dict(self.gps_coverage),
                'gps_coverage_percent':round(100*self.located_events/self.events,1) if self.events else None,
                'retained_wifi':sum(d.obs.protocol=='wifi' for d in self.devices.values()),
                'retained_ble':sum(d.obs.protocol=='ble' for d in self.devices.values()),
                'alerted_addresses':len(self.alerted_keys)}

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.ended_mono=time.monotonic()
        self.stream.close()
        self.discoveries.close()
        summary = {"version": "1.0.8", "rules_version": self.detector.version,
                   "started": self.started, "ended": time.time(), "observations_processed": self.events,
                   "addresses_retained": len(self.devices), "evictions": self.evicted,
                   "log_error": self.log_error, "excluded": sorted(self.excluded),
                   "discovered_addresses": len(self.discovery_keys), "discovery_error": self.discovery_error,
                   "geotagged_observations": self.located_events, "classifications_run": self.classifications}
        summary['field_summary']=self.field_summary()
        summary.update(scan_profile=self.config.get('scan_profile','survey'),privacy_mode=self.config.get('privacy_mode',False),watch_rules=len(self.config.get('watch_rules',[])),observation_bytes=self.bytes_written,discovery_bytes=self.discovery_bytes,limit_bytes=self.log_limit)
        summary["reliability"]=self.reliability
        summary["checkpoint_error"]=self.checkpoint_error
        summary["oui_lookup"] = self.vendor_status
        summary["bluetooth_lookup"] = self.bluetooth_status
        self.write_inventory(self.path / "devices.csv")
        from .recovery import atomic_json
        atomic_json(self.path/"summary.json",summary)

    def write_inventory(self,path):
        with path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["protocol", "address", "name", "last_rssi_dbm", "first_seen_unix",
                             "last_seen_unix", "observations", "classification", "rule_rank", "evidence",
                             "mac_vendor", "vendor_lookup_status", "bluetooth_context_json", "observed_ssids_json", "first_location_json", "last_location_json", "strongest_location_json", "local_label", "bookmarked", "security_json", "known"])
            for device in self.visible():
                obs = device.obs
                hit = device.hits[0] if device.hits else None
                # Quoted CSV fields still need spreadsheet-formula protection.
                name = device.ap_name or obs.name
                if name.lstrip().startswith(("=", "+", "-", "@")):
                    name = "'" + name
                vendor_name = device.vendor.get("name", "")
                if vendor_name.lstrip().startswith(("=", "+", "-", "@")):
                    vendor_name = "'" + vendor_name
                writer.writerow([obs.protocol, obs.address, name, obs.rssi, device.first_seen,
                                 obs.timestamp, device.seen, hit.label if hit else "Unclassified",
                                 hit.score if hit else "", hit.evidence if hit else "", vendor_name,
                                 device.vendor.get("status", "unavailable"),
                                 json.dumps(device.bluetooth, ensure_ascii=True, separators=(",", ":")),
                                 json.dumps(device.ssid_names,ensure_ascii=True,separators=(",", ":")),
                                 json.dumps(device.first_location),json.dumps(device.last_location),
                                 json.dumps(device.strongest_location),
                                 ("'" if self.config.get('device_notes',{}).get(device_key(obs),{}).get('label','').lstrip().startswith(('=','+','-','@')) else '')+self.config.get('device_notes',{}).get(device_key(obs),{}).get('label',''),
                                 self.config.get('device_notes',{}).get(device_key(obs),{}).get('bookmark',False),json.dumps(device.security),self.config.get('device_notes',{}).get(device_key(obs),{}).get('known',False)])
            stream.flush();os.fsync(stream.fileno())

    def checkpoint(self,force=False):
        now=time.monotonic()
        if self.closed or (not force and now<self.next_checkpoint):return
        self.next_checkpoint=now+15
        try:
            for stream in (self.stream,self.discoveries):stream.flush();os.fsync(stream.fileno())
            slot=(self.checkpoint_generation+1)%2;name='devices-checkpoint-%d.csv'%slot
            temporary=self.path/(name+'.tmp')
            self.write_inventory(temporary);os.chmod(temporary,0o600);temporary.replace(self.path/name)
            data={'version':'1.0.8','started':self.started,'checkpointed':time.time(),'inventory':name,
                  'observation_bytes':self.bytes_written,'discovery_bytes':self.discovery_bytes,
                  'observations_processed':self.events,'geotagged_observations':self.located_events,'gps_reasons':dict(self.gps_coverage),
                  'addresses_retained':len(self.devices),'evictions':self.evicted,'field_summary':self.field_summary(),
                  'reliability':self.reliability,'log_error':self.log_error,'discovery_error':self.discovery_error}
            from .recovery import atomic_json
            atomic_json(self.path/'checkpoint.json',data)
            self.checkpoint_at=data['checkpointed'];self.checkpoint_generation+=1;self.checkpoint_error=''
        except OSError as exc:self.checkpoint_error='Checkpoint failed: '+str(exc)[:120]
