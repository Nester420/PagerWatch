# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded radio telemetry; counts decoded management observations, not airtime."""
import threading
import time

class Coverage:
    def __init__(self):
        self.lock=threading.Lock();self.rows={};self.plan=set();self.current=None;self.mode='starting';self.received_total=0;self.last_receive=None;self.unknown_frequency_frames=0
    def configure(self,frequencies,current=None,mode='current'):
        with self.lock:
            self.plan=set(frequencies[:256]);self.mode=mode;self.current=current
            for freq in self.plan:self.rows.setdefault(freq,{'frequency':freq,'visits':0,'frames':0,'rejected':0,'last_selected':None,'last_rx':None})
    def _row(self,freq):
        if freq is None:return None
        if freq not in self.rows:
            if len(self.rows)>=256:return None
            self.rows[freq]={'frequency':freq,'visits':0,'frames':0,'rejected':0,'last_selected':None,'last_rx':None}
        return self.rows[freq]
    def visit(self,freq):
        with self.lock:
            self.current=freq;row=self._row(freq)
            if row:row['visits']+=1;row['last_selected']=time.time()
    def reject(self,freq):
        with self.lock:
            row=self._row(freq)
            if row:row['rejected']+=1
    def receive(self,obs):
        with self.lock:
            self.received_total+=1;self.last_receive=obs.timestamp
            if obs.frequency is None:self.unknown_frequency_frames+=1
            row=self._row(obs.frequency)
            if row:row['frames']+=1;row['last_rx']=obs.timestamp
    def snapshot(self):
        with self.lock:
            rows=[dict(v,planned=f in self.plan) for f,v in sorted(self.rows.items())]
            return {'mode':self.mode,'current_frequency':self.current,'planned':len(self.plan),
                    'visited':sum(bool(r['visits']) for r in rows if r['planned']),
                    'decoded_frames':self.received_total,'last_received':self.last_receive,'unknown_frequency_frames':self.unknown_frequency_frames,
                    'measurement':'AP scan observations' if self.mode=='passive AP scan' else 'decoded management frames','rejected':sum(r['rejected'] for r in rows),
                    'channels':rows}
