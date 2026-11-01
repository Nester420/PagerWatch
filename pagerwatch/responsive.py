# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded work for physical input, feedback and background checkpoint writes."""
import csv
import os
import queue
import threading
import time
from .recovery import atomic_json

class ButtonReader:
    def __init__(self,pager):
        self.pager=pager
        self.queued=callable(getattr(pager,'get_input_event',None))

    def read(self):
        if self.queued:
            presses=[]
            try:
                # Process complete press/release pairs in order, including short taps.
                for _ in range(32):
                    event=self.pager.get_input_event()
                    if event is None:break
                    if event[1]==getattr(self.pager,'EVENT_PRESS',1):presses.append(event[0])
                return presses
            except AttributeError:
                self.queued=False
        _,pressed,_=self.pager.poll_input()
        return [pressed] if pressed else []

class Feedback:
    """One worker, one pending pulse, rate limited; never sleeps in input handling."""
    def __init__(self,pager):
        self.pager=pager;self.jobs=queue.Queue(maxsize=1)
        self.stop=threading.Event();self.thread=None;self.next_pulse=0

    def pulse(self):
        now=time.monotonic()
        if self.stop.is_set() or now<self.next_pulse:return
        self.next_pulse=now+2
        try:self.jobs.put_nowait(120)
        except queue.Full:return
        if self.thread is None:
            self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:duration=self.jobs.get(timeout=.2)
            except queue.Empty:continue
            if not self.stop.is_set():
                try:self.pager.vibrate(duration)
                except (AttributeError,OSError):pass

    def close(self):
        self.stop.set()
        if self.thread:self.thread.join(timeout=.5)

class CheckpointWrite:
    """Receives immutable CSV rows; never traverses a live Session from a thread."""
    def __init__(self,path,rows,data,generation):
        self.path=path;self.rows=rows;self.data=data;self.generation=generation
        self.error='';self.thread=threading.Thread(target=self.run,daemon=True)
        self.thread.start()

    def run(self):
        try:
            # Independent file handles avoid locking the live buffered log writers.
            for name in ('observations.jsonl','discoveries.jsonl'):
                with (self.path/name).open('rb') as stream:os.fsync(stream.fileno())
            target=self.path/self.data['inventory'];temporary=target.with_suffix('.csv.tmp')
            with temporary.open('w',newline='',encoding='utf-8') as stream:
                os.chmod(temporary,0o600);csv.writer(stream).writerows(self.rows)
                stream.flush();os.fsync(stream.fileno())
            temporary.replace(target)
            atomic_json(self.path/'checkpoint.json',self.data)
        except Exception as exc:self.error='Checkpoint failed: '+str(exc)[:120]
        finally:self.rows=None
