# SPDX-License-Identifier: GPL-3.0-or-later
"""Private, bounded diagnostic snapshots. No radio mutations or uploads."""
import json
import os
import platform
import shutil
import subprocess
import time
import zipfile
from . import __version__


def snapshot(session, workers):
    ble = workers.get('BLE')
    rules_sha=getattr(session.detector,'rules_sha256',None)
    return {'rules':{'version':session.detector.version,'sha256':rules_sha,'alert_threshold':session.config.get('alert_threshold',75)},
            'receiver_health':{name:getattr(getattr(w,'receive_health',None),'snapshot',lambda:{})() for name,w in workers.items()},
            'detection_checks':getattr(workers.get('Web'),'detection_check_snapshot',lambda:[])(),
            'version':__version__, 'time':time.time(),
            'reliability':getattr(session,'reliability',{}),'startup_checks':getattr(session,'preflight',[]),'checkpoint_error':getattr(session,'checkpoint_error',''),
            'runtime':{'python':platform.python_version(),'machine':platform.machine()},
            'performance':{'load_average':list(os.getloadavg()) if hasattr(os,'getloadavg') else [],
                           'process_cpu_seconds':time.process_time(),
                           'classifications_run':getattr(session,'classifications',None),
                           'geotagged_observations':getattr(session,'located_events',0)},
            'phone_gps':workers['Web'].phone.status() if 'Web' in workers else None,
            'scanners':{name:worker.status for name,worker in workers.items()},
            'bluetooth_metrics':dict(getattr(ble,'metrics',{})),
            'signature_candidates':list(getattr(ble,'signature_candidates',{}).values()),
            'flipper_candidates':list(getattr(ble,'candidates',{}).values()),
            'cache_only_candidates':list(getattr(ble,'cached_candidates',[])),
            'ble_diagnostics':list(getattr(ble,'diagnostics',[])),
            'wifi_adapters':getattr(workers.get('Wi-Fi'),'adapter_snapshot',lambda:{})(),
            'wifi_link_lifecycle':list(getattr(workers.get('Wi-Fi'),'link_diagnostics',[])),
            'wifi_coverage':workers['Wi-Fi'].coverage.snapshot() if hasattr(workers.get('Wi-Fi'),'coverage') else {},
            'wifi_channel_diagnostics':getattr(workers.get('Wi-Fi'),'channel_diagnostics',[]),
            'settings':{key:session.config.get(key) for key in
                        ('wifi_interface','wifi_scan_mode','ble_backend','ble_controller','ble_hci_interface','ble_info_lookup')},
            'field':{'profile':session.config.get('scan_profile','survey'),'privacy':session.config.get('privacy_mode',False),'tracked_key':getattr(session,'tracked_key',None),'watch_rules':len(session.config.get('watch_rules',[])),'storage':getattr(session,'storage',{})},
            'excluded_count':len(session.excluded),
            'retained':len(session.devices),'processed':session.events,
            'tools':{tool:shutil.which(tool) for tool in ('iw','tcpdump','bluetoothctl','hcitool','hcidump','hciconfig','opkg','setsid')}}


def export_report(session, workers):
    report = snapshot(session,workers)
    inspection=[]
    for args in (['iw','dev'],['ip','-details','link','show'],['bluetoothctl','list'],['bluetoothctl','show'],['bluetoothctl','devices'],['hciconfig'],['hcitool','dev'],['dmesg']):
        try:
            result=subprocess.run(args,capture_output=True,text=True,timeout=3)
            inspection.append({'command':args,'code':result.returncode,'stdout':result.stdout[:16384],'stderr':result.stderr[:4096]})
        except (OSError,subprocess.TimeoutExpired) as exc:
            inspection.append({'command':args,'error':str(exc)})
    report['inspection']=inspection
    temporary=session.path/'diagnostic-report.tmp'
    destination=session.path/'diagnostic-report.zip'
    with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('diagnostics.json',json.dumps(report,indent=2)+'\n')
        samples=getattr(getattr(workers.get('BLE'),'receive_health',None),'sample_snapshot',lambda:[])()
        archive.writestr('advertisement-samples.jsonl',''.join(json.dumps(row)+'\n' for row in samples))
        archive.writestr('detection-checks.json',json.dumps(report['detection_checks'],indent=2)+'\n')
        from pathlib import Path
        for path in (getattr(session,'watchdog_path',None),Path('/tmp/pagerwatch-startup.log')):
            if path:
                path=Path(path)
                try:
                    if path.is_file() and not path.is_symlink():
                        with path.open('rb') as stream:stream.seek(max(0,path.stat().st_size-65536));archive.writestr(path.name,stream.read(65536))
                except OSError:pass
        archive.writestr('README.txt','PagerWatch diagnostic snapshot.\nIncludes nearby Bluetooth addresses/names, bounded advertisement samples, local controller/interface details and recent receive data. Samples are the latest 64 address/source records, at most 128 KiB, and are not a complete packet capture. Raw HCI samples contain advertising_data_hex; BlueZ samples contain properties and their receive source. No GPS is included in advertisement samples. Original identifiers remain in downloads even in Privacy mode.\nNo pairing, connection, adapter reset or online upload was performed by the report collector.\n')
    os.chmod(temporary,0o600)
    temporary.replace(destination)
    return destination
