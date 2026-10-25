# SPDX-License-Identifier: GPL-3.0-or-later
"""Background radio transitions and a diagnostic heartbeat for the Pager UI."""
import faulthandler
import os
import queue
import signal
import threading
import time
from contextlib import contextmanager

class RadioCoordinator:
    """Nonblocking ownership across adapter selection and recovery."""
    def __init__(self):self.lock=threading.Lock();self.owner=None;self.frequency=None;self.since=None
    def claim(self,owner,frequency=None):
        with self.lock:
            if self.owner is not None:return False
            self.owner=owner;self.frequency=frequency;self.since=time.monotonic();return True
    def release(self,owner):
        with self.lock:
            if self.owner!=owner:return False
            self.owner=None;self.frequency=None;self.since=None;return True
    def snapshot(self):
        with self.lock:return {'owner':self.owner,'frequency':self.frequency,'age_seconds':round(max(0,time.monotonic()-self.since),1) if self.since is not None else None}
    @contextmanager
    def operation(self,owner):
        acquired=self.claim(owner)
        try:yield acquired
        finally:
            if acquired:self.release(owner)

class RadioChange:
    def __init__(self):self.thread=None;self.results=queue.Queue(maxsize=1);self.pending=None;self.cancelled=threading.Event()
    def close(self):
        self.cancelled.set()
        item=self.poll()
        if item and item[-1][0]:
            threading.Thread(target=item[-1][1].stop,daemon=True,name='pagerwatch-finish-radio').start()
    def submit(self,key,previous,factory,sink,config,option,value,request=None):
        if self.pending:raise ValueError('Radio change already in progress; please wait')
        coordinator=getattr(previous,'operations',None)
        if coordinator and not coordinator.claim('radio-change'):raise ValueError('Wi-Fi radio busy with adapter selection / receiver recovery; retry shortly')
        self.pending=key
        def change():
            try:
                if previous:
                    previous.stop()
                    thread=getattr(previous,'thread',None)
                    if thread and thread.is_alive():raise RuntimeError('Previous receiver still stopping; retry shortly')
                if self.cancelled.is_set():raise RuntimeError('Payload is finishing')
                replacement=factory(sink,dict(config,**{option:value}));replacement.start()
                if self.cancelled.is_set():replacement.stop();raise RuntimeError('Payload is finishing')
                result=(True,replacement)
            except Exception as exc:result=(False,str(exc)[:200])
            finally:
                if coordinator:coordinator.release('radio-change')
            self.results.put((key,option,value,request,result))
        self.thread=threading.Thread(target=change,daemon=True,name='pagerwatch-radio-change');self.thread.start()
    def poll(self):
        try:item=self.results.get_nowait()
        except queue.Empty:return None
        self.pending=None;return item

class Heartbeat:
    """Record blocked Python stacks; isolated launcher can restore the Pager UI."""
    def __init__(self,path,isolated=False,stale=45,recover=75,clock=time.monotonic):
        self.path=path;self.isolated=isolated;self.stale=stale;self.recover=recover;self.clock=clock
        self.last=clock();self.stop_event=threading.Event();self.reported=False;self.thread=None
    def beat(self):self.last=self.clock()
    def check(self):
        age=self.clock()-self.last
        if age<self.stale:self.reported=False;return 'healthy'
        if not self.reported:
            self.reported=True
            try:
                self.path.parent.mkdir(parents=True,exist_ok=True)
                if not self.path.is_symlink():
                    with self.path.open('w') as stream:
                        stream.write('PagerWatch UI heartbeat stalled for %.1f seconds\n'%age);stream.flush()
                        faulthandler.dump_traceback(file=stream,all_threads=True)
                    self.path.chmod(0o600)
            except OSError:pass
        return 'recover' if self.isolated and age>=self.recover else 'stalled'
    def start(self):
        def watch():
            while not self.stop_event.wait(2):
                if self.check()=='recover':os._exit(70)
        self.thread=threading.Thread(target=watch,daemon=True,name='pagerwatch-heartbeat');self.thread.start()
    def close(self):self.stop_event.set()
