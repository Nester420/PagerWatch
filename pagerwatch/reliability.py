# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded recovery, read-only startup checks and low-frequency process telemetry."""
from collections import deque
import hashlib
import os
from pathlib import Path
import shutil
import time
import queue
import threading

def install_check(root):
    root=Path(root);manifest=root/'SHA256SUMS';problems=[]
    if not manifest.is_file():return {'ok':False,'checked':0,'problems':['Release checksum file missing']}
    checked=0
    for line in manifest.read_text().splitlines():
        try:
            digest,name=line.split('  ',1);path=root/name
            if len(digest)!=64 or path.is_symlink() or path.resolve().is_relative_to(root.resolve()) is False:raise ValueError()
            actual=hashlib.sha256(path.read_bytes()).hexdigest()
            if actual!=digest:problems.append(name+' differs from this release')
            checked+=1
        except (OSError,ValueError):problems.append('Missing or invalid release file: '+line[-100:])
    return {'ok':bool(checked and not problems),'checked':checked,'problems':problems[:20]}

def startup_checks(root,path,config,integrity):
    checks=[{'name':'Release files','state':'pass' if integrity['ok'] else 'fail','detail':str(integrity['checked'])+' files verified' if integrity['ok'] else '; '.join(integrity['problems'])}]
    try:
        free=shutil.disk_usage(path).free
        checks.append({'name':'Recording storage','state':'pass' if free>=50*1048576 else 'warn','detail':'%.0f MB free'%(free/1048576)})
    except OSError:checks.append({'name':'Recording storage','state':'fail','detail':'Cannot inspect storage'})
    if config.get('wifi_enabled',True):
        for tool in ('iw','tcpdump'):
            checks.append({'name':'Wi-Fi '+tool,'state':'pass' if shutil.which(tool) else 'fail','detail':'Available' if shutil.which(tool) else 'Missing'})
    if config.get('ble_enabled',True):
        ok=bool(shutil.which('bluetoothctl') or shutil.which('hcitool'))
        checks.append({'name':'Bluetooth tools','state':'pass' if ok else 'fail','detail':'Receiver tools available; capture checked at runtime' if ok else 'No bluetoothctl or hcitool'})
    return checks

class Reliability:
    def __init__(self):
        self.events=deque(maxlen=32);self.retries={};self.gps_was_valid=False;self.gps_gaps=0
        self.capture='';self.last_sample=0;self.last_cpu=time.process_time();self.metrics={};self.next_recovery=0;self.recovery_jobs={};self.recovery_results=queue.Queue();self.cancelled=threading.Event()
    def close(self):
        self.cancelled.set()
        # Workers check cancellation on both sides of receiver startup.
        for thread in list(self.recovery_jobs.values()):thread.join(timeout=.2)
        self.finish_recoveries({},closing=True)

    def finish_recoveries(self,workers,closing=False):
        while True:
            try:key,original,replacement,error,coordinator=self.recovery_results.get_nowait()
            except queue.Empty:break
            try:
                self.recovery_jobs.pop(key,None);entry=self.retries.get(key)
                if replacement and (closing or self.cancelled.is_set() or workers.get(key) is not original):
                    threading.Thread(target=replacement.stop,daemon=True).start();continue
                if not entry:continue
                if replacement:
                    workers[key]=replacement
                    entry.update(worker=id(replacement),next=0,started=time.monotonic(),recovery_stopped=False)
                    self.record('Receiver retry',key+' passive receiver restarted')
                else:
                    entry.update(next=time.monotonic()+min(120,5*2**min(entry['attempts'],5)),last_error=error)
                    self.record('Receiver retry failed',key+': '+str(error))
            finally:
                if coordinator:coordinator.release('receiver-recovery')

    def recover(self,key,worker,factory,sink,config,entry):
        if key in self.recovery_jobs or self.cancelled.is_set():return
        settings=dict(config)
        coordinator=getattr(worker,'operations',None)
        if coordinator and not coordinator.claim('receiver-recovery'):return
        entry['attempts']+=1;entry['recovery_stopped']=True
        def run():
            replacement=None;error=''
            try:
                worker.stop()
                if worker.thread.is_alive():raise RuntimeError('Previous receiver still stopping')
                if self.cancelled.is_set():raise RuntimeError('Payload is finishing')
                replacement=factory(sink,settings);replacement.start()
                if self.cancelled.is_set():replacement.stop();replacement=None;error='Payload is finishing'
            except Exception as exc:
                error=str(exc)[:200]
                if replacement:
                    try:replacement.stop()
                    except Exception:pass
                    replacement=None
            finally:
                if self.cancelled.is_set() and coordinator:coordinator.release('receiver-recovery')
                self.recovery_results.put((key,worker,replacement,error,coordinator))
        thread=threading.Thread(target=run,daemon=True,name='pagerwatch-recover-'+key);self.recovery_jobs[key]=thread;thread.start()

    def record(self,kind,message):
        self.events.append({'time':time.time(),'kind':kind,'message':str(message)[:180]})
    def tick(self,workers,factories,config,sink,gps,queue_size,dropped):
        self.finish_recoveries(workers)
        now=time.monotonic()
        capture=getattr(workers.get('Wi-Fi'),'capture_interface','')
        if capture and capture!=self.capture:self.record('Capture source',capture);self.capture=capture
        valid=bool(gps.get('valid'))
        if self.gps_was_valid and not valid:
            self.gps_gaps+=1;self.record('GPS gap','Fresh phone GPS lost; new observations need a usable fix')
        elif valid and not self.gps_was_valid:self.record('GPS restored','Fresh phone GPS available')
        self.gps_was_valid=valid
        # A quiet RF environment is never a reason to restart a receiver.
        if now>=self.next_recovery:
            self.next_recovery=now+1
            for key,factory in factories.items():
                worker=workers.get(key);thread=getattr(worker,'thread',None)
                if not worker or thread is None:continue
                entry=self.retries.setdefault(key,{'attempts':0,'next':0,'worker':id(worker),'last_error':''})
                if entry['worker']!=id(worker):entry.update(worker=id(worker),attempts=0,next=0,paused=False,recovery_stopped=False)
                if thread.is_alive():
                    # After a minute alive, the next independent failure gets a short delay.
                    if entry.get('started') is not None and now-entry['started']>=60:entry.update(attempts=0,paused=False)
                    continue
                if key in self.recovery_jobs or self.cancelled.is_set():continue
                if worker.stop_event.is_set() and not entry.get('recovery_stopped'):continue
                if not entry['next']:
                    entry['next']=now+min(120,5*2**min(entry['attempts'],5));entry['last_error']=worker.status
                    self.record('Receiver stopped',key+': '+worker.status)
                if now<entry['next']:continue
                if entry['attempts']>=6:
                    if not entry.get('paused'):
                        entry['paused']=True;self.record('Receiver recovery paused',key+': six failed retries; choose the receiver manually to retry')
                    continue
                self.recover(key,worker,factory,sink,config,entry)
        if now-self.last_sample>=5:
            cpu=time.process_time();elapsed=now-self.last_sample
            rss=None
            try:
                with open('/proc/self/statm') as stream:rss=int(stream.read(256).split()[1])*os.sysconf('SC_PAGE_SIZE')
            except (OSError,ValueError,IndexError):pass
            self.metrics={'cpu_percent_one_core':round(100*(cpu-self.last_cpu)/elapsed,1) if self.last_sample else None,
                          'rss_bytes':rss,'queue_depth':queue_size,'queue_drops':dropped}
            self.last_sample=now;self.last_cpu=cpu
    def snapshot(self):
        now=time.monotonic()
        return {'events':list(self.events),'gps_gaps':self.gps_gaps,'performance':dict(self.metrics),
                'receivers':{k:{'attempts':r['attempts'],'retry_in':round(max(0,r['next']-now),1) if r['next'] else None,'last_error':r['last_error'],'paused':r.get('paused',False),'recovering':k in self.recovery_jobs} for k,r in self.retries.items()}}
