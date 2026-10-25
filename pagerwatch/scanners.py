# SPDX-License-Identifier: GPL-3.0-or-later
"""Linux radio adapters. No injection, association, or GATT connections."""
import json
from collections import OrderedDict, deque
import os
import pty
import queue
import re
import select
import signal
import shutil
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from .adapters import adapter_rows, interface_metadata, valid_interface
from .hci import RawHciParser, AdvertisementCache, hcitool_name, open_hci_events, hci_event
from .detection import Observation
from .parsers import BluezParser, PcapReader, bluez_cached_properties


def interface_admin_up(name):
    """IFF_UP is authoritative; monitor operstate may correctly be 'unknown'."""
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}",name):
        raise ValueError("Invalid interface name")
    try:
        with open("/sys/class/net/"+name+"/flags") as stream:
            return bool(int(stream.read().strip(),16)&1)
    except (OSError,ValueError):
        return None


def command(args, timeout=12):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip()[-300:])
    return result.stdout


def current_frequency(text):
    match = re.search(r"\bchannel\s+\d+\s+\((\d+)(?:\.0+)?\s+MHz\)",text,re.I)
    if not match:
        match = re.search(r"(?m)^\s*(?:freq(?:uency)?\s*[:=]?\s+)(\d+)(?:\.0+)?\s*(?:MHz)?\s*$",text,re.I)
    return int(match.group(1)) if match else None


def interfaces(text=None):
    text = command(["iw", "dev"], timeout=2) if text is None else text
    found, current, phy = [], None, None
    for line in text.splitlines():
        physical = re.match(r"\s*phy#(\d+)", line)
        if physical:
            phy = "phy" + physical.group(1)
        match = re.match(r"\s*Interface\s+(\S+)", line)
        if match:
            current = {"name": match.group(1), "type": "unknown", "frequency": None, "phy": phy}
            found.append(current)
        elif current:
            address = re.match(r'\s*addr\s+([0-9a-f:]{17})', line, re.I)
            if address:current['address']=address.group(1).upper()
            kind = re.match(r"\s*type\s+(\S+)", line)
            freq = current_frequency(line)
            if kind:
                current["type"] = kind.group(1)
            if freq is not None:
                current["frequency"] = freq
    return found


SCAN_MODES = ("dual", "2.4", "5", "current")
MODE_NAMES = {"dual": "2.4 + 5 GHz sweep", "2.4": "2.4 GHz sweep",
              "5": "5 GHz sweep", "current": "Current channel"}


def supported_frequencies(text):
    """Use the driver's current frequency permissions, never a hardcoded country list.

    NO-IR/DFS entries can be valid for receive-only monitor tuning. The driver
    has the final say; a rejected tune is skipped and reported for this session.
    """
    result = set()
    for line in text.splitlines():
        match = re.search(r"\*\s+(\d+)(?:\.0+)?\s+MHz\s+\[\d+\]", line)
        if match and "disabled" not in line.lower():
            result.add(int(match.group(1)))
    return sorted(result)


def band_plan(frequencies, mode):
    low = [f for f in frequencies if 2400 <= f < 2500]
    high = [f for f in frequencies if 4900 <= f < 5925]
    if mode == "2.4":
        return low
    if mode == "5":
        return high
    if mode != "dual":
        raise ValueError("Unknown automatic band plan: " + mode)
    # Interleave bands so neither waits for a whole sweep of the other band.
    result = []
    for index in range(max(len(low), len(high))):
        if index < len(low):
            result.append(low[index])
        if index < len(high):
            result.append(high[index])
    return result


def radio_frequencies(item):
    phy = item.get("phy")
    if not phy:
        info = command(["iw", "dev", item["name"], "info"], timeout=4)
        match = re.search(r"\bwiphy\s+(\d+)", info)
        if not match:
            raise RuntimeError("Cannot identify capture radio for " + item["name"])
        phy = "phy" + match.group(1)
        item["phy"] = phy
    diagnostics = item.setdefault("channel_queries", [])
    for args in (["iw", "phy", phy, "info"], ["iw", "phy", phy, "channels"], ["iw", "list"]):
        try:
            output = command(args, timeout=4)
        except (RuntimeError, subprocess.TimeoutExpired) as exc:
            diagnostics.append({"command": args, "error": str(exc)})
            continue
        diagnostics.append({"command": args, "output": output[:65536]})
        if args == ["iw", "list"]:
            # Never borrow another radio's regulatory/channel permissions.
            blocks = re.split(r"(?m)^(?=Wiphy\s+)", output)
            output = "\n".join(block for block in blocks
                               if re.match(r"Wiphy\s+" + re.escape(phy) + r"(?:\s|$)", block))
        frequencies = supported_frequencies(output)
        if frequencies:
            return frequencies
    return []


def scan_mode(config):
    return config.get("wifi_scan_mode", "custom" if config.get("allow_channel_hop", False) else "current")


def shared_radio_users(selected, available, timeout=12):
    """Avoid retuning an AP or a connected managed interface on the same PHY."""
    if not selected.get("phy"):
        raise RuntimeError("Cannot identify shared radio users")
    blockers = []
    for item in available:
        if item["name"] == selected["name"] or item.get("phy") != selected["phy"]:
            continue
        if item["type"].lower() in ("ap", "p2p-go", "mesh", "mesh point", "ibss"):
            blockers.append(item["name"])
        elif item["type"] == "managed":
            try:
                link = command(["iw", "dev", item["name"], "link"], timeout=timeout)
            except Exception:
                blockers.append(item["name"])
            else:
                if "Not connected" not in link:
                    blockers.append(item["name"])
    return blockers


def parse_iw(text, now):
    result = []
    obs = None
    age = 0
    def flush():
        if obs and age <= 5000:
            obs.timestamp = now - age / 1000
            result.append(obs)
    for line in text.splitlines():
        bss = re.match(r"BSS\s+([0-9a-f:]{17})", line, re.I)
        if bss:
            flush()
            obs = Observation("wifi", bss.group(1).upper(), timestamp=now, frame="scan_result")
            age = 0
        elif obs:
            value = line.strip()
            if value.startswith("SSID:"):
                obs.name = value[5:].lstrip()
                obs.ssid_status="advertised" if obs.name.replace("\\x00", "") else "hidden"
                if obs.ssid_status=="hidden":obs.name=""
            elif value.startswith("signal:"):
                number = re.search(r"-?\d+(?:\.\d+)?", value)
                if number:
                    obs.rssi = int(float(number.group()))
            elif value.startswith("freq:"):
                obs.frequency = int(value.split(":", 1)[1])
            elif value.startswith("last seen:"):
                number = re.search(r"\d+", value)
                age = int(number.group()) if number else 999999
    flush()
    return result


class Worker:
    def __init__(self, sink):
        self.sink = sink
        self.stop_event = threading.Event()
        self.thread = None
        self.status = "not started"
        self.proc = None
        self.process_lock=threading.RLock()

    def start(self):
        self.thread = threading.Thread(target=self.guarded, daemon=True)
        self.thread.start()

    def guarded(self):
        try:
            self.run()
        except Exception as exc:
            if not self.stop_event.is_set():
                self.status = "ERROR: " + str(exc)[:180]
        finally:
            self.close_process()

    def close_process(self):
        # stop() and the receiver's finally block can race during a USB removal.
        # Do not terminate or close the same pipe from both threads at once.
        with self.process_lock:
            proc=self.proc
            if proc and proc.poll() is None:
                try:
                    proc.terminate()
                    try:proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=2)
                except ProcessLookupError:pass
            if proc:
                for stream in (proc.stdin,proc.stdout,proc.stderr):
                    if stream:
                        try:stream.close()
                        except (OSError,ValueError):pass
            self.proc=None

    def stop(self):
        self.stop_event.set()
        self.close_process()
        if self.thread:
            self.thread.join(timeout=15)


from .coverage import Coverage


class WifiWorker(Worker):
    def __init__(self, sink, config):
        super().__init__(sink)
        self.config = config
        self.channel_diagnostics = []
        self.coverage = Coverage()
        self.target_frequency = None
        self.tracking_status = "Sweep / not tracking"
        self.current_frequency = None
        self.link_change = None
        self.link_diagnostics = []
        self.adapter_lock = threading.Lock()
        self.adapters = []
        self.adapter_error = ''
        self.inventory_thread = None
        self.adapter_selected = ''
        self.capture_interface = ''
        self.owned_monitor = None
        self.monitor_original_frequency = None
        self.adapter_reasons = []
        self.capture_running = False
        self.adapter_refresh_event=threading.Event()
        from .runtime import RadioCoordinator
        self.operations=RadioCoordinator()

    def publish_adapters(self, available):
        rows=adapter_rows(available)
        for row in rows:row['owned']=bool(self.owned_monitor and row['name']==self.owned_monitor[0] and row.get('phy')==self.owned_monitor[1])
        with self.adapter_lock:self.adapters=rows;self.adapter_error=''

    def health_snapshot(self):
        data=self.coverage.snapshot();last=data.get('last_received')
        running=bool(self.proc and self.proc.poll() is None) or self.capture_running or bool(data.get('mode')=='passive AP scan' and self.thread and self.thread.is_alive())
        return {'receiving':last is not None and 0<=time.time()-last<30,
                'running':running,'observations':data.get('decoded_frames',0),'last_received':last,
                'age_seconds':max(0,round(time.time()-last,1)) if last is not None else None,
                'meaning':data.get('measurement','decoded observations')}

    def adapter_issue(self,name,reason):
        with self.adapter_lock:
            self.adapter_reasons=[r for r in self.adapter_reasons if r['interface']!=name][-31:]+[{'interface':name,'reason':str(reason)[:180]}]

    def adapter_snapshot(self):
        health=self.health_snapshot()
        with self.adapter_lock:
            return {'interfaces':[dict(row) for row in self.adapters], 'error':self.adapter_error,
                    'requested':self.config.get('wifi_interface','auto'), 'selected':self.adapter_selected,
                    'capture':self.capture_interface,'health':health,'skipped':list(self.adapter_reasons),
                    'operation':self.operations.snapshot(),
                    'capabilities':{'monitor_capture':next((r['type']=='monitor' for r in self.adapters if r['name']==self.capture_interface),None),
                                    'receive_verified':health['receiving'],
                                    'note':'Monitor configuration and confirmed packet reception are reported separately.'},
                    'policy':getattr(self,'adapter_policy_status','Manual / legacy selection'),
                    'transitions':list(getattr(self,'adapter_transitions',[])),
                    'retries':list(getattr(self,'adapter_retry_status',[])),
                    'refreshing':bool(self.inventory_thread and self.inventory_thread.is_alive())}

    def refresh_adapters(self):
        self.adapter_refresh_event.set()
        if self.inventory_thread and self.inventory_thread.is_alive():return
        def read():
            try:self.publish_adapters(interfaces())
            except Exception as exc:
                with self.adapter_lock:self.adapter_error=str(exc)[:160]
        self.inventory_thread=threading.Thread(target=read,daemon=True)
        self.inventory_thread.start()

    def usb_idle(self, selected, available):
        blockers=shared_radio_users(selected,available)
        if selected['type']=='managed':
            link=command(['iw','dev',selected['name'],'link'],timeout=3)
            if 'Not connected' not in link:blockers.append(selected['name'])
        # Do not borrow a station carrying a non-link-local IP address.
        for item in available:
            if item.get('phy')!=selected.get('phy') or item.get('type')!='managed':continue
            text=command(['ip','addr','show','dev',item['name']],timeout=3)
            if re.search(r'\binet\s+(?!169\.254\.)',text) or re.search(r'\binet6\s+(?!fe[89ab][0-9a-f]:|::1(?:/|\s))',text,re.I):
                blockers.append(item['name']+' (IP address)')
        if blockers:raise RuntimeError('USB radio busy: '+','.join(dict.fromkeys(blockers))+'; choose a dedicated adapter')

    def prepare_usb_monitor(self, selected, available):
        if not selected.get('phy') or not re.fullmatch(r'phy[0-9]+',selected['phy']):
            radio_frequencies(selected)
        if not shutil.which('ip'):raise RuntimeError('ip tool required to verify an unused USB adapter')
        self.usb_idle(selected,available)
        info=command(['iw','phy',selected['phy'],'info'],timeout=4)
        modes=re.search(r'Supported interface modes:\s*\n((?:[ \t]+\*[^\n]+\n?)+)',info)
        if not modes or not re.search(r'\*\s+monitor\s*$',modes[1],re.M):
            self.link_diagnostics.append({'interface':selected['name'],'action':'monitor unsupported; passive AP scan only'})
            return selected
        if not shutil.which('tcpdump'):raise RuntimeError('tcpdump missing for USB monitor capture')
        name='pwmon'+secrets.token_hex(3)
        if any(i['name']==name for i in available):raise RuntimeError('Temporary monitor name conflict; retry adapter selection')
        self.owned_monitor=(name,selected['phy'])
        self.monitor_original_frequency=selected.get('frequency')
        command(['iw','phy',selected['phy'],'interface','add',name,'type','monitor'],timeout=4)
        fresh=interfaces()
        created=next((i for i in fresh if i['name']==name and i.get('phy')==selected['phy'] and i['type']=='monitor'),None)
        if not created:raise RuntimeError('USB driver did not expose the temporary monitor; see diagnostics')
        self.usb_idle(created,fresh)
        if created.get('frequency') is None:created['frequency']=selected.get('frequency')
        self.link_diagnostics.append({'interface':name,'source':selected['name'],'phy':selected['phy'],'action':'created owned monitor'})
        return created

    def remove_owned_monitor(self):
        if not self.owned_monitor:return
        name,phy=self.owned_monitor
        try:
            found=next((i for i in interfaces() if i['name']==name),None)
            if found and found.get('phy')==phy and found['type']=='monitor':
                command(['iw','dev',name,'del'],timeout=3)
                self.link_diagnostics.append({'interface':name,'action':'removed owned monitor'})
            elif found:
                self.link_diagnostics.append({'interface':name,'action':'cleanup refused: interface identity changed'})
        except Exception as exc:
            self.link_diagnostics.append({'interface':name,'action':'owned monitor cleanup failed','error':str(exc)[:160]})
        self.owned_monitor=None

    def track_frequency(self, frequency):
        if frequency is not None and (isinstance(frequency,bool) or not isinstance(frequency,int) or not 2400<=frequency<5925):
            self.target_frequency = None
            self.tracking_status = "Target channel unknown; sweep continues"
            return False
        self.target_frequency = frequency
        self.tracking_status = "Requesting target %s MHz" % frequency if frequency else "Sweep / not tracking"
        return True


    def run(self):
        if self.config.get('wifi_interface')=='adaptive':
            return self.run_adaptive()
        return self.run_once()

    def run_adaptive(self):
        from .adapters import adaptive_candidates,AdapterRetries
        child=None;identity=None;signature=None;retry=AdapterRetries();next_check=0;next_probe=0;failed_child=None
        self.adapter_retry_status=[]
        self.adapter_policy_status='Detecting external / Pager radios'
        self.adapter_transitions=[]
        try:
            while not self.stop_event.is_set():
                now=time.monotonic()
                if self.adapter_refresh_event.is_set():
                    self.adapter_refresh_event.clear();retry.entries.clear();signature=None;next_check=0
                if now>=next_check:
                    next_check=now+1
                    try:
                        available=interfaces()
                        self.publish_adapters(available)
                        topology=tuple(sorted((i['name'],i.get('phy'),i['type']) for i in available if not i['name'].startswith('pwmon')))
                        present={(i['name'],i.get('phy')) for i in available}
                        retry.reconcile(present)
                        alive=bool(child and child.thread and child.thread.is_alive())
                        if child and not alive and id(child)!=failed_child:
                            retry.fail(identity,now);failed_child=id(child)
                            self.adapter_issue(identity[0],child.status)
                            self.adapter_policy_status='Receiver stopped; retry / fallback: '+child.status[:100]
                        # Do not reprobe idle/IP/band state on every UI frame.
                        if topology!=signature or not alive or retry.due(now) or now>=next_probe:
                            with self.operations.operation('adapter-change') as allowed:
                                if allowed:
                                    next_probe=now+5
                                    desired=None
                                    for candidate in adaptive_candidates(available):
                                        key=(candidate['name'],candidate.get('phy'))
                                        if not retry.ready(key,now):continue
                                        try:
                                            self.usb_idle(candidate,available)
                                            mode=scan_mode(self.config)
                                            if mode!='current' and not band_plan(radio_frequencies(candidate),mode):
                                                self.adapter_issue(candidate['name'],'No enabled channels for selected band');retry.fail(key,now);continue
                                        except Exception as exc:
                                            self.adapter_issue(candidate['name'],exc)
                                            retry.fail(key,now)
                                            continue
                                        desired=candidate;break
                                    key=(desired['name'],desired.get('phy')) if desired else None
                                    if key!=identity or not alive:
                                        if child:
                                            child.stop()
                                            if child.thread and child.thread.is_alive():
                                                self.status='Waiting for previous Wi-Fi receiver to stop'
                                                continue
                                        child=None;identity=None
                                        self.adapter_selected='';self.capture_interface=''
                                        if desired:
                                            cfg=dict(self.config,wifi_interface=desired['name'])
                                            child=WifiWorker(self.sink,cfg)
                                            child.track_frequency(self.target_frequency)
                                            identity=key
                                            self.adapter_policy_status=('External USB: ' if desired['external'] else 'Pager fallback: ')+desired['name']
                                            self.adapter_transitions.append({'interface':desired['name'],'phy':desired.get('phy'),'policy':self.adapter_policy_status,'time':time.time()})
                                            self.adapter_transitions=self.adapter_transitions[-32:]
                                            child.start()
                                        else:self.status='Waiting for a suitable external or Pager radio'
                                    signature=topology
                        self.adapter_retry_status=retry.snapshot(now)
                    except Exception as exc:
                        with self.adapter_lock:self.adapter_error=str(exc)[:160]
                        if not child:self.status='Adapter discovery failed; retrying'
                if child:
                    self.capture_running=bool(child.proc and child.proc.poll() is None) if hasattr(child,'proc') else False
                    child.track_frequency(self.target_frequency) if child.target_frequency!=self.target_frequency else None
                    for name in ('status','coverage','current_frequency','tracking_status','adapter_selected','capture_interface','channel_diagnostics','link_diagnostics'):
                        setattr(self,name,getattr(child,name))
                    with self.adapter_lock:
                        for row in self.adapters:
                            row['owned']=bool(child.owned_monitor and row['name']==child.owned_monitor[0] and row.get('phy')==child.owned_monitor[1])
                self.stop_event.wait(.2)
        finally:
            if child:child.stop()
            self.capture_running=False

    def run_once(self):
        self.owned_monitor = None
        self.link_change = None
        self.link_diagnostics = []
        try:
            self.run_capture()
        finally:
            if self.link_change and self.owned_monitor and self.link_change[0]==self.owned_monitor[0]:
                # This interface did not exist before the payload: deletion below
                # is its restoration, including when USB unplug already removed it.
                self.link_change=None
            if self.link_change:
                name, tool = self.link_change
                try:
                    args = [tool,"link","set","dev",name,"down"] if tool=="ip" else [tool,name,"down"]
                    command(args,timeout=3)
                    self.link_diagnostics.append({"interface":name,"action":"restore original DOWN","ok":True})
                except (OSError,RuntimeError,subprocess.TimeoutExpired) as exc:
                    self.status = "ERROR: capture stopped; cannot restore %s DOWN: %s" % (name,str(exc)[:80])
                    self.link_diagnostics.append({"interface":name,"action":"restore original DOWN","error":str(exc)})
                self.link_change = None
            self.remove_owned_monitor()

    def ensure_monitor_up(self,name):
        state = interface_admin_up(name)
        self.link_diagnostics.append({"interface":name,"original_admin_up":state})
        if state is not False:
            return
        tool = "ip" if shutil.which("ip") else "ifconfig" if shutil.which("ifconfig") else None
        if not tool:
            raise RuntimeError(name+" is DOWN; ip/ifconfig unavailable to bring it up")
        self.status = "Bringing selected monitor "+name+" UP"
        # Save ownership before the command, so timeout/partial success also rolls back.
        self.link_change = (name,tool)
        args = [tool,"link","set","dev",name,"up"] if tool=="ip" else [tool,name,"up"]
        try:
            command(args,timeout=3)
        except (OSError,RuntimeError,subprocess.TimeoutExpired) as exc:
            self.link_diagnostics.append({"interface":name,"action":"bring UP","error":str(exc)})
            raise RuntimeError("Cannot bring "+name+" UP: "+str(exc)) from exc
        if interface_admin_up(name) is not True:
            raise RuntimeError("Driver did not confirm "+name+" UP; capture not started")
        self.link_diagnostics.append({"interface":name,"action":"bring UP","ok":True})

    def run_capture(self):
        if not shutil.which("iw"):
            raise RuntimeError("iw missing")
        available = interfaces()
        self.publish_adapters(available)
        mode = scan_mode(self.config)
        wanted = self.config.get("wifi_interface", "auto")
        if wanted == "auto":
            choices = [i for i in available if i["type"] == "monitor"]
            # Passive iw scan is a limited fallback; does not see client probes.
            choices += [i for i in available if i["type"] == "managed"]
        elif wanted == 'usb':
            choices=[i for i in available if i['type'] in ('monitor','managed') and interface_metadata(i['name'])['usb']]
            choices.sort(key=lambda i:i['type']!='monitor')
        else:
            if not valid_interface(wanted):raise RuntimeError('Invalid Wi-Fi interface name')
            choices = [i for i in available if i["name"] == wanted and i['type'] in ('monitor','managed')]
        if not choices:
            raise RuntimeError("Selected Wi-Fi adapter unavailable: "+wanted+"; refresh adapters/check driver or choose Auto")
        # Prefer a monitor that actually supports the requested bands, rather
        # than a 2.4-only monitor merely listed first by iw.
        if wanted == "auto" and mode in ("dual", "2.4", "5"):
            ranked = []
            for candidate in choices:
                try:
                    frequencies = radio_frequencies(candidate)
                    plan = band_plan(frequencies, mode)
                    bands = int(any(f < 2500 for f in plan)) + int(any(f >= 4900 for f in plan))
                    shared_ap = any(i.get("phy") == candidate.get("phy") and i.get("name") != candidate.get("name") and i.get("type","").lower() in ("ap","p2p-go","mesh","mesh point","ibss") for i in available)
                    rank = (int(candidate["type"] == "monitor"), int(not shared_ap), bands, int(candidate.get("frequency") is not None), len(plan))
                    if plan:
                        ranked.append((rank, candidate))
                except Exception:
                    continue
            if ranked:
                choices = [max(ranked, key=lambda pair: pair[0])[1]]
        selected = choices[0]
        self.adapter_selected=selected['name']
        if selected['type']=='managed' and interface_metadata(selected['name'])['usb']:
            selected=self.prepare_usb_monitor(selected,available)
            available=interfaces()
            self.publish_adapters(available)
        name = selected["name"]
        self.capture_interface=name
        channels = []
        coverage = mode
        fallback = ""
        if mode in ("dual", "2.4", "5"):
            try:
                frequencies = radio_frequencies(selected)
            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                selected.setdefault("channel_queries", []).append({"error": str(exc)})
                frequencies = []
            self.channel_diagnostics = [{"interface": i["name"], "phy": i.get("phy"),
                                         "queries": i.get("channel_queries", [])} for i in available]
            channels = band_plan(frequencies, mode)
            if not channels:
                if selected["type"] != "monitor":
                    raise RuntimeError("Channel list unavailable for passive AP scan; see scanner_status.json")
                fallback = " / LIMITED: current channel; sweep unavailable"

            low_count = sum(f < 2500 for f in channels)
            high_count = len(channels) - low_count
            coverage = "2.4:%d 5:%d" % (low_count, high_count)
        elif mode == "custom":
            channels = [int(f) for f in self.config.get("hop_frequencies", [])]
        elif mode != "current":
            raise RuntimeError("Invalid wifi_scan_mode")
        if selected["type"] != "monitor":
            self.coverage.configure(channels,selected.get("frequency"),"passive AP scan")
            while not self.stop_event.is_set():
                self.status = name + " passive AP scan (no probes) / " + mode
                try:
                    args = ["iw", "dev", name, "scan"]
                    if channels:
                        args += ["freq"] + [str(f) for f in channels]
                    args += ["passive"]
                    text = command(args, timeout=12)
                    for obs in parse_iw(text, time.time()):
                        self.coverage.receive(obs)
                        if not self.stop_event.is_set():
                            self.sink(obs)
                except (RuntimeError, subprocess.TimeoutExpired) as exc:
                    self.status = "ERROR: passive scan: " + str(exc)[:100]
                self.stop_event.wait(5)
            return
        if not shutil.which("tcpdump"):
            raise RuntimeError("tcpdump missing for monitor capture")
        self.ensure_monitor_up(name)
        hop = bool(channels)
        if selected.get("frequency") is None or self.link_change:
            try:
                output = command(["iw","dev",name,"info"],timeout=3)
                selected["frequency"] = current_frequency(output)
                selected.setdefault("channel_queries",[]).append({"command":["iw","dev",name,"info"],"output":output[:4096]})
            except (RuntimeError,subprocess.TimeoutExpired) as exc:
                selected.setdefault("channel_queries",[]).append({"error":str(exc)})
        self.current_frequency = selected.get("frequency")
        if self.owned_monitor and selected.get('frequency') is None:
            if not channels:
                raise RuntimeError('Temporary USB monitor needs a known enabled channel; choose a band sweep')
            # New, owned monitor has no channel to preserve. Do not apply this
            # exception to an existing monitor with an unknown original channel.
            command(['iw','dev',name,'set','freq',str(channels[0])],timeout=3)
            selected['frequency']=self.current_frequency=channels[0]
        if hop and selected.get("frequency") is None:
            hop = False
            fallback = " / LIMITED: current channel; original frequency unknown"
        if hop:
            # Populate the PHY even for legacy custom plans.
            if not selected.get("phy"):
                radio_frequencies(selected)
            blockers = shared_radio_users(selected, available)
            if blockers:
                raise RuntimeError("Sweep blocked: shared AP/connection " + ",".join(blockers) + "; choose Current channel")
        self.coverage.configure(channels,selected.get('frequency'),'sweep' if hop else 'current channel')
        with tempfile.TemporaryFile() as errors:
            self.proc = subprocess.Popen(["tcpdump", "-i", name, "-n", "-U", "-s", "1024",
                                          "-w", "-", "type mgt"],
                                         stdout=subprocess.PIPE, stderr=errors)
            proc = self.proc
            self.coverage.visit(self.current_frequency)
            parser = PcapReader()
            next_hop = 0
            channel_index = 0
            held_frequency = None
            rejected_target = None
            eligible = set(channels) if hop else {selected.get("frequency")}
            failed = set()
            pending = {}
            next_emit = time.monotonic() + 1
            next_guard = time.monotonic()+5
            self.status = name + (" monitor / hopping" if hop else " monitor / current channel") + fallback
            try:
                while not self.stop_event.is_set() and proc.poll() is None:
                    if time.monotonic()>=next_guard:
                        fresh=interfaces()
                        if not any(i['name']==name and i.get('phy')==selected.get('phy') for i in fresh):
                            raise RuntimeError('USB capture interface disappeared; refresh adapters or choose Auto')
                        if self.owned_monitor:self.usb_idle(selected,fresh)
                        next_guard=time.monotonic()+5
                    target = self.target_frequency
                    if target is not None and target not in eligible:
                        self.tracking_status = "Cannot hold target: channel unavailable; scanning continues"
                        target = None
                    elif target is not None and target == rejected_target:
                        target = None
                    if target is not None and held_frequency != target:
                        if target == self.current_frequency:
                            held_frequency = target
                        elif hop:
                            try:
                                command(["iw","dev",name,"set","freq",str(target)],timeout=3)
                                self.current_frequency = held_frequency = target
                                self.coverage.visit(target)
                            except (RuntimeError,subprocess.TimeoutExpired):
                                self.coverage.reject(target)
                                rejected_target = target
                                self.tracking_status = "Target tune rejected; scanning continues"
                                target = None
                        if held_frequency == target and target is not None:
                            self.tracking_status = "HOLD %d MHz / selected target" % target
                    if target is None and held_frequency is not None:
                        held_frequency = None
                        next_hop = 0
                        if not hop:
                            self.status = name + " monitor / current channel" + fallback
                    if self.target_frequency is None:
                        rejected_target = None
                    if target is not None:
                        self.status = name + " / " + self.tracking_status
                    if hop and target is None and time.monotonic() >= next_hop:
                        usable = [f for f in channels if f not in failed]
                        if not usable:
                            raise RuntimeError("Driver rejected every frequency in the sweep")
                        frequency = usable[channel_index % len(usable)]
                        try:
                            command(["iw", "dev", name, "set", "freq", str(frequency)], timeout=3)
                        except (RuntimeError, subprocess.TimeoutExpired):
                            self.coverage.reject(frequency)
                            failed.add(frequency)
                            self.status = name + " / rejected %s MHz (%d skipped)" % (frequency, len(failed))
                            continue
                        self.current_frequency = frequency
                        self.coverage.visit(frequency)
                        band = "2.4" if frequency < 2500 else "5"
                        self.status = "%s / %s sweep: %s GHz %s MHz [%d/%d; skip %d]" % (
                            name, coverage, band, frequency, channel_index % len(usable) + 1, len(usable), len(failed))
                        channel_index += 1
                        next_hop = time.monotonic() + max(0.2, float(self.config.get("hop_seconds", 0.5)))
                    ready, _, _ = select.select([proc.stdout], [], [], 0.2)
                    if time.monotonic() >= next_emit:
                        for obs in pending.values():
                            self.sink(obs)
                        pending.clear()
                        next_emit = time.monotonic() + 1
                    if not ready:
                        continue
                    data = os.read(proc.stdout.fileno(), 65536)
                    if not data:
                        break
                    for obs in parser.feed(data):
                        self.coverage.receive(obs)
                        identity = (obs.address, obs.frame)
                        previous = pending.get(identity)
                        if previous is None or (bool(obs.name),obs.rssi if obs.rssi is not None else -127) >= (bool(previous.name),previous.rssi if previous.rssi is not None else -127):
                            if len(pending) < 2048 or identity in pending:
                                pending[identity] = obs
                if not self.stop_event.is_set():
                    errors.seek(0)
                    self.status = "ERROR: capture stopped: " + errors.read().decode(errors="replace")[-160:]
            finally:
                for obs in pending.values():
                    self.sink(obs)
                self.close_process()
                restore=self.monitor_original_frequency if self.owned_monitor else selected.get('frequency')
                if hop and restore is not None:
                    try:
                        if self.owned_monitor:self.usb_idle(selected,interfaces())
                        command(["iw", "dev", name, "set", "freq", str(restore)], timeout=3)
                    except Exception as exc:
                        self.link_diagnostics.append({'interface':name,'action':'channel restore failed or unsafe','error':str(exc)[:160]})
                        self.status = "ERROR: original channel restore failed: " + str(exc)



class BleWorker(Worker):
    def __init__(self, sink, config):
        super().__init__(sink)
        self.config = config
        self.diagnostics = deque(maxlen=128)
        self.metrics = {"backend":"starting", "controller":"unknown", "receiver":"none",
                        "raw_packets":0,"decoded_reports":0,"name_lines":0,"observations":0,
                        "last_packet":0,"last_observation":0,"last_error":""}
        self.candidates = OrderedDict()
        self.cached_candidates = []

    def emit(self, obs):
        self.metrics["observations"] += 1
        self.metrics["last_observation"] = obs.timestamp
        reason = []
        if any(u.lower() in {"3080","3081","3082","3083"} or
               u.lower() in {"0000"+n+"-0000-1000-8000-00805f9b34fb" for n in ("3080","3081","3082","3083")} for u in obs.uuids+list(obs.service_data)):
            reason.append("service")
        if "flipper" in obs.name.lower():
            reason.append("name")
        if obs.address.upper().startswith(("0C:FA:22:","80:E1:26:")):
            reason.append("address prefix (type: "+obs.address_type+")")
        if "3625" in obs.manufacturer:
            reason.append("company")
        if reason:
            self.candidates.pop(obs.address,None)
            self.candidates[obs.address] = {"observation":obs.to_dict(),"reason":reason}
            while len(self.candidates)>32:
                self.candidates.popitem(last=False)
        self.sink(obs)

    def run(self):
        if shutil.which("bluetoothctl"):
            try:
                inventory = command(["bluetoothctl","devices"],timeout=2)
                for line in inventory.splitlines():
                    match = re.match(r"Device\s+([0-9A-Fa-f:]{17})\s*(.*)",line)
                    if match:
                        address,name = match.groups()
                        if "flipper" in name.lower() or address.upper().startswith(("80:E1:26:","0C:FA:22:")):
                            self.cached_candidates.append({"address":address.upper(),"name":name,"source":"BlueZ known-device cache; not a live sighting"})
                            if len(self.cached_candidates)>=32:
                                break
                self.diagnostics.append("BlueZ cache-only candidates: %d"%len(self.cached_candidates))
            except (RuntimeError,subprocess.TimeoutExpired) as exc:
                self.diagnostics.append("Device inventory unavailable: "+str(exc))
        backend = self.config.get("ble_backend", "auto")
        if backend not in ("auto", "bluez", "hcitool"):
            raise RuntimeError("ble_backend must be auto, bluez or hcitool")
        if backend == "hcitool" or backend == "auto" and shutil.which("hcitool"):
            try:
                self.run_hcitool()
                return
            except Exception as exc:
                self.diagnostics.append("HCITOOL ERROR: " + str(exc))
                self.metrics["last_error"] = str(exc)
                if backend == "hcitool" or self.stop_event.is_set():
                    raise
                self.status = "hcitool unavailable; trying BlueZ"
        self.run_bluez()

    def run_bluez(self):
        if not shutil.which("bluetoothctl"):
            raise RuntimeError("bluetoothctl missing (bluez-utils)")
        self.metrics["backend"] = "bluez"
        self.metrics["receiver"] = "BlueZ properties"
        controller = self.config.get("ble_controller", "")
        if controller and not re.fullmatch(r"[0-9A-Fa-f:]{17}", controller):
            raise RuntimeError("ble_controller must be a controller MAC address")
        show = command(["bluetoothctl", "show"] + ([controller] if controller else []), timeout=4)
        if "Powered: yes" not in show:
            raise RuntimeError("Bluetooth controller off; enable it before scanning")
        match = re.search(r"Controller\s+([0-9a-fA-F:]{17})",show)
        self.metrics["controller"] = match.group(1) if match else controller or "default"
        parser = BluezParser()
        master, slave = pty.openpty()
        try:
            self.proc = subprocess.Popen(["bluetoothctl"], stdin=slave, stdout=slave,
                                         stderr=slave, close_fds=True)
            os.close(slave)
            slave = None
            commands = (["select " + controller] if controller else []) + [
                "menu scan", "transport le", "duplicate-data on", "back", "scan on"]
            for item in commands:
                os.write(master, (item + "\n").encode())
                if self.stop_event.wait(0.15):
                    return
            self.status = "BLE discovery requested / waiting for events"
            pending = b""
            last_flush = time.monotonic()
            queried = OrderedDict()
            next_info = 0
            proc = self.proc
            while not self.stop_event.is_set() and proc.poll() is None:
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    chunk = os.read(master, 8192)
                    if not chunk:
                        break
                    pending = (pending + chunk)[-65536:]
                    while b"\n" in pending:
                        line, _, pending = pending.partition(b"\n")
                        text = line.decode(errors="replace").replace("\r", "")
                        self.diagnostics.append(text[-512:])
                        if "Failed to" in text or "No default controller" in text:
                            self.status = "ERROR: " + text[-130:]
                            self.metrics["last_error"] = text[-130:]
                        elif "Discovery started" in text:
                            self.status = "BlueZ BLE discovery active"
                        parser.feed(text)
                if time.monotonic() - last_flush >= 1:
                    observations = parser.drain()
                    for obs in observations:
                        self.emit(obs)
                    tick = time.monotonic()
                    if self.config.get("ble_info_lookup", True) and not controller and tick >= next_info:
                        candidates = [o for o in observations if tick - queried.get(o.address, -999) >= 120]
                        candidates.sort(key=lambda o: (not o.name.lower().startswith("flipper"), bool(o.uuids)))
                        if candidates:
                            obs = candidates[0]
                            queried[obs.address] = tick
                            queried.move_to_end(obs.address)
                            if len(queried) > 512:
                                queried.popitem(last=False)
                            next_info = tick + 2
                            try:
                                info = command(["bluetoothctl", "info", obs.address], timeout=2)
                                self.diagnostics.append("INFO " + obs.address + "\n" + info[:4096])
                                enriched = bluez_cached_properties(obs, info)
                                if enriched and time.time() - obs.timestamp <= 15:
                                    self.emit(enriched)
                                    # Retain metadata with its source until normal evidence expiry.
                                    entry = parser.devices.get(obs.address)
                                    if entry:
                                        entry["obs"] = enriched
                                        for uuid in enriched.uuids:
                                            entry["evidence_times"][("uuid", uuid)] = obs.timestamp
                                        for kind, table in (("mfg", enriched.manufacturer), ("svc", enriched.service_data)):
                                            for key in table:
                                                entry["evidence_times"][(kind, key)] = obs.timestamp
                            except (RuntimeError, subprocess.TimeoutExpired) as exc:
                                self.diagnostics.append("INFO ERROR " + obs.address + ": " + str(exc))
                    last_flush = time.monotonic()
            if not self.stop_event.is_set() and not self.status.startswith("ERROR"):
                self.status = "ERROR: bluetoothctl stopped"
        finally:
            # Only stop this child's discovery session; never kill other scanners.
            try:
                os.write(master, b"scan off\nquit\n")
                if self.proc:
                    self.proc.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
            self.close_process()
            os.close(master)
            if slave is not None:
                os.close(slave)


    def stop(self):
        self.stop_event.set()
        proc = self.proc
        if proc and proc.poll() is None:
            try:
                proc.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass
        if self.thread:
            self.thread.join(timeout=8)
        self.close_process()

    def hci_interface(self):
        explicit = self.config.get("ble_hci_interface", "auto")
        controller = self.config.get("ble_controller", "")
        if explicit != "auto":
            if not re.fullmatch(r"hci[0-9]+", explicit):
                raise RuntimeError("ble_hci_interface must be auto or hciN")
            return explicit
        if not shutil.which("hciconfig"):
            if controller:
                raise RuntimeError("hciconfig needed to map the selected Bluetooth MAC")
            return "hci0"
        output = command(["hciconfig"], timeout=3)
        self.diagnostics.append("CONTROLLERS\n" + output[:4096])
        if not controller and shutil.which("bluetoothctl"):
            try:
                show = command(["bluetoothctl", "show"], timeout=3)
                match = re.search(r"Controller\s+([0-9A-Fa-f:]{17})", show)
                controller = match.group(1) if match else ""
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
        blocks = re.split(r"(?m)^(?=hci[0-9]+:)", output)
        for block in blocks:
            name = re.match(r"(hci[0-9]+):", block)
            if name and (controller and controller.upper() in block.upper() or not controller and "UP RUNNING" in block):
                return name.group(1)
        raise RuntimeError("Cannot identify a powered HCI controller; choose BlueZ or enable Bluetooth")

    def run_hcitool(self):
        if not shutil.which("hcitool"):
            raise RuntimeError("hcitool is unavailable; choose BlueZ")
        hci = self.hci_interface()
        self.metrics["backend"] = "hcitool"
        self.metrics["controller"] = hci
        cache, raw_parser = AdvertisementCache(), RawHciParser()
        children, masters, buffers, kinds = [], [], {}, {}
        counts = {"name":0,"raw":0}

        def launch(args, kind):
            master, slave = pty.openpty()
            try:
                proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=slave, stderr=slave, close_fds=True)
            except Exception:
                os.close(master)
                raise
            finally:
                os.close(slave)
            children.append(proc)
            masters.append(master)
            buffers[master] = b""
            kinds[master] = kind
            return proc

        raw_proc = None
        raw_socket = None
        try:
            try:
                raw_socket = open_hci_events(hci)
                self.diagnostics.append("RAW HCI receive socket open on " + hci)
                self.metrics["receiver"] = "raw HCI socket"
            except (OSError,AttributeError,TypeError,ValueError) as exc:
                self.diagnostics.append("RAW HCI socket unavailable: " + str(exc))
                self.metrics["last_error"] = "Raw socket: " + str(exc)
            if raw_socket is None and shutil.which("hcidump"):
                raw_proc = launch(["hcidump", "-i", hci, "--raw"], "raw")
                self.metrics["receiver"] = "hcidump"
            self.proc = launch(["hcitool", "-i", hci, "lescan", "--duplicates"], "name")
            scan = self.proc
            while not self.stop_event.is_set() and scan.poll() is None:
                ready, _, _ = select.select(list(buffers)+([raw_socket] if raw_socket else []), [], [], 0.2)
                for descriptor in ready:
                    if descriptor is raw_socket:
                        try:
                            packet = raw_socket.recv(4096)
                        except BlockingIOError:
                            continue
                        self.metrics["raw_packets"] += 1
                        self.metrics["last_packet"] = time.time()
                        self.diagnostics.append("HCI PACKET " + packet[:260].hex())
                        for obs in hci_event(packet):
                            counts["raw"] += 1
                            self.metrics["decoded_reports"] += 1
                            self.diagnostics.append("HCI ADV " + obs.address + " " + obs.name + " UUID " + ",".join(obs.uuids))
                            self.emit(cache.merge(obs))
                        continue
                    try:
                        chunk = os.read(descriptor, 8192)
                    except OSError:
                        chunk = b""
                    if not chunk:
                        buffers.pop(descriptor,None)
                        continue
                    buffers[descriptor] = (buffers[descriptor]+chunk)[-65536:]
                    while b"\n" in buffers[descriptor]:
                        line, _, buffers[descriptor] = buffers[descriptor].partition(b"\n")
                        text = line.decode(errors="replace").replace("\r", "")
                        kind = kinds[descriptor]
                        self.diagnostics.append(kind.upper()+": "+text[-512:])
                        if kind == "raw":
                            observations = raw_parser.feed(text)
                        else:
                            obs = hcitool_name(text)
                            observations = [obs] if obs else []
                        for obs in observations:
                            counts[kind] += 1
                            self.metrics["decoded_reports" if kind == "raw" else "name_lines"] += 1
                            if kind == "raw":
                                self.metrics["last_packet"] = time.time()
                            self.emit(cache.merge(obs))
                raw_active = raw_socket is not None or raw_proc is not None and raw_proc.poll() is None
                if not raw_active:
                    self.metrics["receiver"] = "names only"
                self.status = "%s hcitool | names %d | raw %d%s" % (hci, counts["name"], counts["raw"],
                    "" if raw_active else " (names only; no RSSI/UUID)")
            if not self.stop_event.is_set():
                raise RuntimeError("hcitool scan stopped; see Bluetooth diagnostics")
        finally:
            # SIGINT lets hcitool disable its own scan. No adapter resets or killall.
            for proc in reversed(children):
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=1)
            self.proc = None
            if raw_socket is not None:
                raw_socket.close()
            for descriptor in masters:
                os.close(descriptor)


class GpsWorker(Worker):
    def __init__(self, config):
        super().__init__(lambda _: None)
        self.host = config.get("gpsd_host", "127.0.0.1")
        self.port = int(config.get("gpsd_port", 2947))
        self.fix = None

    def run(self):
        while not self.stop_event.is_set():
            try:
                with socket.create_connection((self.host, self.port), timeout=2) as sock:
                    sock.settimeout(1)
                    sock.sendall(b'?WATCH={"enable":true,"json":true};\n')
                    pending = b""
                    while not self.stop_event.is_set():
                        try:
                            chunk = sock.recv(4096)
                        except socket.timeout:
                            continue
                        if not chunk:
                            break
                        pending = (pending + chunk)[-32768:]
                        while b"\n" in pending:
                            line, _, pending = pending.partition(b"\n")
                            try:
                                data = json.loads(line)
                            except ValueError:
                                continue
                            if data.get("class") == "TPV":
                                if data.get("mode", 0) >= 2 and "lat" in data and "lon" in data:
                                    self.fix = {"lat": data["lat"], "lon": data["lon"], "received": time.time()}
                                    self.status = "GPS fix"
                                else:
                                    self.fix = None
                                    self.status = "GPS no fix"
            except OSError:
                self.status = "GPS unavailable (optional)"
            self.fix = None
            self.stop_event.wait(5)

    def current(self, observation_time):
        fix = self.fix
        if fix and 0 <= observation_time - fix["received"] <= 5:
            return {"lat": fix["lat"], "lon": fix["lon"]}
        return None
