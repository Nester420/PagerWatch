# SPDX-License-Identifier: GPL-3.0-or-later
"""CLI and on-device orchestration."""
import argparse
import json
import os
import shutil
from pathlib import Path
import queue
import signal
import sys
import time
import threading
from .detection import Detector, Observation
from .scanners import WifiWorker, BleWorker, GpsWorker, command, interfaces, SCAN_MODES, scan_mode
from .session import Session
from .diagnostics import export_report, snapshot
from .vendors import VendorLookup
from .bluetooth_labels import BluetoothLabels
from .fieldtools import apply_note,apply_rule,PROFILES,validate_rule,validate_note,gps_health
from .archive import SessionArchive
from .config_backup import read_pending,pending_path,stage_restore
from .reliability import Reliability,install_check,startup_checks

BLE_DATA = "third_party/wardrive-go/ble_vendor_data.json"

ROOT = Path(__file__).resolve().parent.parent


def load_config(path):
    with (ROOT / "config.example.json").open() as stream:
        config = json.load(stream)
    if path.exists():
        with path.open() as stream:
            config.update(json.load(stream))
    pending=read_pending(path)
    if pending is not None:config.update(pending)
    if not 1 <= int(config["max_devices"]) <= 10000:
        raise ValueError("max_devices must be 1..10000")
    if not 1 <= int(config["max_log_mb"]) <= 1000:
        raise ValueError("max_log_mb must be 1..1000")
    if not 0 <= int(config["alert_threshold"]) <= 100:
        raise ValueError("alert_threshold must be 0..100")
    if config.get("ble_backend", "auto") not in ("auto", "bluez", "hcitool"):
        raise ValueError("ble_backend must be auto, bluez or hcitool")
    if config.get("wifi_scan_mode") not in SCAN_MODES + ("custom",):
        raise ValueError("wifi_scan_mode must be dual, 2.4, 5, current or custom")
    if config.get('scan_profile','survey') not in PROFILES:raise ValueError('Invalid scan profile')
    if not isinstance(config.get('privacy_mode',False),bool):raise ValueError('Invalid privacy setting')
    if not isinstance(config.get('device_notes',{}),dict) or len(config.get('device_notes',{}))>2000:raise ValueError('Invalid local labels')
    for key,value in config.get('device_notes',{}).items():validate_note(dict(value,key=key))
    if not isinstance(config.get('watch_rules',[]),list) or len(config.get('watch_rules',[]))>64:raise ValueError('Invalid watchlist')
    config['watch_rules']=[validate_rule(value) for value in config.get('watch_rules',[])]
    if pending is not None:
        save_config(path,config);pending_path(path).unlink()
    return config


def save_config(path, config):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(config, indent=2) + "\n")
    os.chmod(temporary, 0o600)
    if path.is_file() and not path.is_symlink():
        try:
            json.loads(path.read_text());backup=path.with_suffix(".json.bak.tmp");shutil.copy2(path,backup);os.chmod(backup,0o600);backup.replace(path.with_suffix(".json.bak"))
        except (OSError,ValueError):pass
    temporary.replace(path)


def doctor(config):
    import shutil
    print("PagerWatch 1.0.8 readiness (no radio settings changed)")
    print("Python:", sys.version.split()[0])
    for tool in ("iw", "tcpdump", "bluetoothctl", "hcitool", "hcidump"):
        print(tool + ":", shutil.which(tool) or "MISSING")
    try:
        for item in interfaces():
            print("Wi-Fi:", item)
    except Exception as exc:
        print("Wi-Fi inspection:", exc)
    try:
        print("Bluetooth controllers:\n" + command(["bluetoothctl", "list"], timeout=4))
        print(command(["bluetoothctl", "show"] + ([config["ble_controller"]] if config["ble_controller"] else []), timeout=4))
    except Exception as exc:
        print("Bluetooth inspection:", exc)
    try:
        load_pager()
        print("pagerctl: loadable (display was not initialized)")
    except Exception as exc:
        print("pagerctl:", exc)
    print("Wi-Fi scan mode:", scan_mode(config))
    try:
        import ssl
        print("HTTPS:", ssl.OPENSSL_VERSION)
    except ImportError:
        print("HTTPS: Python ssl module missing; native scanning is still available")
    print("Web management bind:", config.get("web_bind", "172.16.52.1"), config.get("web_port",8443))
    try:
        labels = BluetoothLabels(ROOT / BLE_DATA)
        print("BLE lookup:", labels.company_count, "companies;", labels.service_count, "service owners")
    except (OSError, ValueError, AttributeError) as exc:
        print("BLE lookup unavailable:", exc)
    try:
        lookup = VendorLookup(ROOT / "data/oui_lookup.bin")
        print("OUI lookup:", lookup.count, "prefixes (vendor labels only)")
        lookup.close()
    except (OSError, ValueError) as exc:
        print("OUI lookup unavailable:", exc)


def load_pager():
    locations = [ROOT / "lib", Path("/root/payloads/user/utilities/PAGERCTL"),
                 Path("/mmc/root/payloads/user/utilities/PAGERCTL")]
    for path in locations:
        if (path / "pagerctl.py").is_file() and (path / "libpagerctl.so").is_file():
            sys.path.insert(0, str(path))
            from pagerctl import Pager
            return Pager
    raise RuntimeError("pagerctl missing: run setup.sh --pagerctl /path/to/PAGERCTL")


def main():
    parser = argparse.ArgumentParser(description="PagerWatch Wi-Fi/BLE prototype")
    parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    parser.add_argument("--rules", type=Path, default=ROOT / "rules.json")
    parser.add_argument("--doctor", action="store_true")
    parser.add_argument("--headless", action="store_true", help="scan without taking over the display")
    parser.add_argument("--seconds", type=float, default=0, help="stop after this many seconds; 0 = until exit")
    parser.add_argument("--replay", type=Path, help="process JSONL observations without accessing radios")
    parser.add_argument("--output", type=Path, help="override local session directory")
    args = parser.parse_args()
    os.umask(0o077)
    integrity=install_check(ROOT)
    if not integrity["ok"] and not args.doctor:
        raise RuntimeError("Incomplete/mixed PagerWatch release: "+"; ".join(integrity["problems"])+". Copy the complete release folder again; preserve config.json and .state.")
    config = load_config(args.config)
    if args.doctor:
        doctor(config)
        return 0
    from .notebook import ResearchStore
    detector = Detector(args.rules)
    session = Session(args.output or config["log_directory"], detector, config)
    session.research_store=ResearchStore(ROOT/'.state/research')
    session.preflight=startup_checks(ROOT,session.path,config,integrity)
    reliability=Reliability()
    workers = {}
    pager = screen = None
    stopped = False
    inbox = queue.Queue(maxsize=1024)
    dropped = 0
    export_thread = None
    export_result = []
    web = None
    web_export = None
    last_publish = 0
    last_draw = 0
    tracking_request = None
    from .runtime import RadioChange,Heartbeat
    radio_change=RadioChange()
    session.radio_change=radio_change
    session.watchdog_path=ROOT/'.state/runtime-watchdog.log'
    heartbeat=Heartbeat(session.watchdog_path,isolated=os.environ.get('PAGERWATCH_ISOLATED')=='1')

    def stop_signal(*_):
        nonlocal stopped
        stopped = True

    def sink(obs):
        nonlocal dropped
        try:
            inbox.put_nowait(obs)
        except queue.Full:
            dropped += 1

    def request_radio(action,value,request=None):
        key='BLE' if action=='ble_backend' else 'Wi-Fi'
        option={'wifi_mode':'wifi_scan_mode','wifi_interface':'wifi_interface','ble_backend':'ble_backend'}[action]
        factory=BleWorker if key=='BLE' else WifiWorker
        radio_change.submit(key,workers.get(key),factory,sink,config,option,value,request)
        if screen:screen.notice('Changing '+key+' adapter / mode in background...')

    def restart_wifi():request_radio('wifi_mode',config.get('wifi_scan_mode','dual'))

    def set_profile(value):
        if radio_change.pending:raise ValueError('Radio change in progress; please wait')
        if value not in PROFILES:raise ValueError('Invalid scan profile')
        changed=config.get('wifi_scan_mode')!='dual'
        config['scan_profile']=value;config['wifi_scan_mode']='dual'
        if value!='track':
            session.tracked_key=None
            if screen:screen.hunt_key=None;screen.hunt_sound=False
        if value=='quiet' and screen:screen.hunt_sound=False
        if changed:restart_wifi()

    signal.signal(signal.SIGTERM, stop_signal)
    signal.signal(signal.SIGINT, stop_signal)
    try:
        try:
            session.vendors = VendorLookup(ROOT / "data/oui_lookup.bin")
            session.vendor_status = "OUI lookup: %d prefixes (vendor only)" % session.vendors.count
        except (OSError, ValueError) as exc:
            session.vendor_status = "OUI lookup unavailable: " + str(exc)
        try:
            session.bluetooth_labels = BluetoothLabels(ROOT / BLE_DATA)
            session.bluetooth_status = "BLE lookup: %d companies / %d services" % (
                session.bluetooth_labels.company_count, session.bluetooth_labels.service_count)
        except (OSError, ValueError, AttributeError) as exc:
            session.bluetooth_status = "BLE lookup unavailable: " + str(exc)
        if args.replay:
            with args.replay.open() as stream:
                for line in stream:
                    if stopped:
                        break
                    data = json.loads(line)
                    session.ingest(Observation(**data.get("observation", data)))
            print("Replay complete:", len(session.devices), "addresses retained;", len(session.alerts), "alerts")
            print("Session:", session.path)
            return 0
        if not args.headless:
            from .ui import Screen
            pager = load_pager()()
            if pager.init() != 0:
                raise RuntimeError("Display initialization failed")
            pager.set_rotation(270)
            screen = Screen(pager, session, workers, lambda: save_config(args.config, config))
            session.alert_callback = screen.notify
            screen.start_splash(ROOT / "assets/startup.png")
        if config.get("wifi_enabled", True):
            workers["Wi-Fi"] = WifiWorker(sink, config)
        if config.get("ble_enabled", True):
            workers["BLE"] = BleWorker(sink, config)
        if config.get("gps_enabled", False):
            workers["GPS"] = GpsWorker(config)
        if config.get("web_enabled", True):
            try:
                from .webserver import WebService
                web = WebService(ROOT, config)
                web.research_store=session.research_store
                workers["Web"] = web
            except Exception as exc:
                session.web_error = "Web unavailable: " + str(exc)
        for worker in workers.values():
            worker.start()
        if web:
            web.publish(session, workers, dropped)
        began = time.monotonic()
        last_report = 0
        heartbeat.start()
        while not stopped:
            heartbeat.beat()
            ingest_until=time.monotonic()+.05
            for _ in range(100):
                if time.monotonic()>=ingest_until:break
                try:
                    obs = inbox.get_nowait()
                except queue.Empty:
                    break
                gps, gps_reason = web.phone.observation_fix(obs.timestamp) if web else (None,"unavailable")
                if gps is None and "GPS" in workers:
                    gps = workers["GPS"].current(obs.timestamp)
                session.ingest(obs, gps, gps_reason)
                if web:
                    web.add_observation(obs, gps, obs.protocol+":"+obs.address.upper() in session.devices,
                                        device=session.devices.get(obs.protocol+":"+obs.address.upper()))
            if web:
                # All scanner/session changes stay on this owning thread.
                for _ in range(4):
                    try:
                        request = web.commands.get_nowait()
                    except queue.Empty:
                        break
                    try:
                        action, value = request["action"], request["value"]
                        if action in ("wifi_mode", "wifi_interface", "ble_backend"):
                            request_radio(action,value,request)
                        elif action=='config_restore':
                            stage_restore(args.config,value);web.restore_pending=True
                            web.result(request,True,'Restore saved. Finish and relaunch PagerWatch to apply it.')
                        elif action=='profile':
                            set_profile(value);save_config(args.config,config)
                            web.result(request,True,'Profile: '+value+(' — select a device to track' if value=='track' and not session.tracked_key else ''))
                        elif action=='privacy':
                            config['privacy_mode']=value;save_config(args.config,config)
                            web.result(request,True,'Privacy mode '+('on' if value else 'off'))
                        elif action=='device_note':
                            apply_note(config,value);save_config(args.config,config);web.result(request,True,'Device details saved')
                        elif action=='watch_rule':
                            apply_rule(config,value);save_config(args.config,config);web.result(request,True,'Watchlist updated; matches apply to new observations')
                        elif action=='session_delete':
                            from .sessiontools import delete_sessions
                            count,size=delete_sessions(SessionArchive(session.path.parent),value,session.path.name)
                            web.result(request,True,'Deleted %d saved runs (%d bytes)'%(count,size))
                        elif action=='session_rename':
                            SessionArchive(session.path.parent).rename(value['id'],value['label']);web.result(request,True,'Session name saved')
                        elif action=='track_target':
                            if value is None:
                                session.tracked_key=None
                                if screen:screen.hunt_key=None;screen.hunt_sound=False
                            else:
                                if value not in session.devices:raise ValueError('Device no longer retained')
                                set_profile('track');session.tracked_key=value
                                if screen:screen.hunt_key=value;screen.hunt_sound=False
                            save_config(args.config,config);web.result(request,True,'Target tracking '+('requested' if value else 'released'))
                        elif action == "wifi_refresh":
                            worker=workers.get('Wi-Fi')
                            if not worker:raise ValueError('Wi-Fi receiver disabled')
                            worker.refresh_adapters()
                            web.result(request,True,'Adapter list refresh requested')
                        elif action == "gps_bridge":
                            if value:
                                web.bridge.start()
                            else:
                                web.bridge.stop()
                            web.result(request, True, web.bridge.status)
                        elif action == "diagnostics":
                            if export_thread is not None:
                                raise ValueError("A diagnostic export is already running")
                            web_export = request
                            def build_web_report():
                                try:
                                    export_result.append((True, str(export_report(session, workers))))
                                except Exception as exc:
                                    export_result.append((False, str(exc)))
                            export_thread = threading.Thread(target=build_web_report, daemon=True)
                            export_thread.start()
                    except Exception as exc:
                        web.result(request, False, str(exc))
            if export_thread is not None and not export_thread.is_alive():
                export_thread = None
                success, result = export_result.pop()
                message = "Diagnostic report ready to download" if success else "Report failed: "+result
                if web_export is not None and web:
                    web.result(web_export, success, message)
                    web_export = None
                if screen:
                    screen.export_busy = False
                    screen.notice(message)
            transition=radio_change.poll()
            if transition:
                key,option,value,request,(success,result)=transition
                if success:
                    workers[key]=result;config[option]=value
                    try:save_config(args.config,config);message=key+' selection: '+str(value)
                    except OSError:message=key+' changed; settings save failed'
                else:message=result
                if request and web:web.result(request,success,message)
                if screen:screen.notice(message)
            if web and web.wants_snapshot() and time.monotonic()-last_publish >= 4:
                web.publish(session, workers, dropped)
                last_publish = time.monotonic()
            if screen:
                _, pressed, _ = pager.poll_input()
                screen.input(pressed)
                if getattr(screen,'adapter_refresh_requested',False):
                    screen.adapter_refresh_requested=False
                    wifi=workers.get('Wi-Fi')
                    if wifi:wifi.refresh_adapters()
                if getattr(screen,'profile_requested',None) is not None:
                    value=screen.profile_requested;screen.profile_requested=None
                    try:set_profile(value);save_config(args.config,config);screen.notice('Profile: '+value)
                    except Exception as exc:screen.notice(str(exc))
                if getattr(screen,'privacy_requested',None) is not None:
                    config['privacy_mode']=screen.privacy_requested;screen.privacy_requested=None
                    try:save_config(args.config,config)
                    except OSError:screen.notice('Privacy active; save failed')
                if screen.mode_requested is not None or screen.adapter_requested is not None:
                    option='wifi_scan_mode' if screen.mode_requested is not None else 'wifi_interface'
                    value=screen.mode_requested if screen.mode_requested is not None else screen.adapter_requested
                    screen.mode_requested=None;screen.adapter_requested=None
                    try:request_radio('wifi_mode' if option=='wifi_scan_mode' else 'wifi_interface',value)
                    except Exception as exc:screen.notice(str(exc))
                if screen.ble_backend_requested is not None:
                    backend = screen.ble_backend_requested
                    screen.ble_backend_requested = None
                    try:request_radio('ble_backend',backend)
                    except Exception as exc:screen.notice(str(exc))
                if screen.export_requested and export_thread is None:
                    screen.export_requested = False
                    screen.export_busy = True
                    def build_report():
                        try:
                            export_result.append((True, str(export_report(session, workers))))
                        except Exception as exc:
                            export_result.append((False, str(exc)))
                    export_thread = threading.Thread(target=build_report,daemon=True)
                    export_thread.start()
                tick = time.monotonic()
                draw_interval = .5 if screen.tab == 3 or screen.hunt_key else 1.0
                if pressed or tick-last_draw >= draw_interval:
                    screen.draw()
                    last_draw = tick
                if screen.exit_requested:
                    break
            elif time.monotonic() - last_report > 5:
                print(json.dumps({"retained": len(session.devices), "live": len(session.live()),
                                  "alerts": len(session.alerts), "queue_drops": dropped,
                                  "log_error": session.log_error,
                                  "scanners": {k: v.status for k, v in workers.items()}}), flush=True)
                last_report = time.monotonic()
            if screen and screen.hunt_key!=session.tracked_key:
                session.tracked_key=screen.hunt_key
                if screen.hunt_key:config['scan_profile']='track'
            wifi=workers.get('Wi-Fi');target=session.devices.get(session.tracked_key)
            frequency=(target.last_frequency or target.obs.frequency) if target and target.obs.protocol=='wifi' else None
            tracking=(session.tracked_key,frequency,id(wifi))
            if wifi and hasattr(wifi,'track_frequency') and tracking!=tracking_request:
                wifi.track_frequency(frequency);tracking_request=tracking
                if target and target.obs.protocol=='wifi' and frequency is None:wifi.tracking_status='Target channel unknown; sweep continues'
            session.gps_status=web.phone.status() if web else {}
            heartbeat.beat()
            if heartbeat.thread is None:heartbeat.start()
            reliability.tick(workers,{"Wi-Fi":WifiWorker,"BLE":BleWorker},config,sink,session.gps_status,inbox.qsize(),dropped)
            session.reliability=reliability.snapshot()
            session.checkpoint()
            session.storage=session.storage_health.snapshot(session)
            if args.seconds and time.monotonic() - began >= args.seconds:
                break
            time.sleep(0.2)
    finally:
        reliability.close()
        heartbeat.close()
        radio_change.close()
        for worker in workers.values():
            worker.stop()
        try:
            if export_thread is not None:
                export_thread.join(timeout=22)
            while not inbox.empty():
                session.ingest(inbox.get_nowait())
            session.close()
            report = snapshot(session, workers)
            report["queue_drops"] = dropped
            (session.path / "scanner_status.json").write_text(json.dumps(report, indent=2) + "\n")
        finally:
            if session.vendors:
                session.vendors.close()
            if pager:
                pager.cleanup()
    return 0
