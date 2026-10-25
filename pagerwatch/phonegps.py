# SPDX-License-Identifier: GPL-3.0-or-later
"""Opt-in phone location and an owned gpsd/PTTY bridge inspired by mobile2gps."""
from collections import deque
from datetime import datetime, timezone
import math
import os
import pty
import shutil
import socket
import subprocess
import threading
import time
import tty


class PhoneGPS:
    def __init__(self,max_accuracy=100,ttl=15):
        self.max_accuracy,self.ttl=max_accuracy,ttl
        self.lock=threading.Lock()
        self.owner=None
        self.fix=None
        self.received=0
        self.mono=0
        self.lease=0
        self.segment=0
        self.trail=deque(maxlen=2048)

    def start(self,owner):
        with self.lock:
            if self.owner not in (None,owner) and time.monotonic()-self.lease<30:
                raise ValueError('Another device is sharing location. Stop it or wait 30 seconds.')
            self.segment+=1
            self.owner=owner;self.lease=time.monotonic();self.fix=None

    def stop(self,owner):
        with self.lock:
            if self.owner not in (None,owner):
                raise ValueError('Location is shared by another device.')
            self.owner=None;self.fix=None

    def submit(self,owner,data):
        values={}
        for key in ('lat','lon','accuracy','timestamp_ms','age_ms'):
            value=data.get(key)
            if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value):
                raise ValueError('Invalid location field: '+key)
            values[key]=float(value)
        if not -90<=values['lat']<=90 or not -180<=values['lon']<=180 or not 0<=values['accuracy']<=100000:
            raise ValueError('Location out of range')
        if not 0<=values['age_ms']<=15000 or not 0<=values['timestamp_ms']<=1e14:
            raise ValueError('Location is stale or its timestamp is invalid')
        # Optional browser speed is meters/second; an absent reading is not zero.
        speed=data.get('speed_mps')
        if speed is not None and (isinstance(speed,bool) or not isinstance(speed,(int,float)) or not math.isfinite(speed) or speed<0):
            raise ValueError('Invalid location field: speed_mps')
        values['speed_mps']=float(speed) if speed is not None else None
        heading=data.get('heading_deg')
        if heading is not None and (isinstance(heading,bool) or not isinstance(heading,(int,float)) or not math.isfinite(heading) or not 0<=heading<360):
            raise ValueError('Invalid location field: heading_deg')
        values['heading_deg']=float(heading) if heading is not None and speed!=0 else None
        with self.lock:
            if owner!=self.owner:
                raise ValueError('Start location sharing on this device first.')
            self.fix=values;self.received=time.time();self.mono=time.monotonic();self.lease=self.mono
            if values['accuracy']<=self.max_accuracy:
                self.trail.append({'lat':values['lat'],'lon':values['lon'],'accuracy':values['accuracy'],
                                   'time':self.received,'source':'phone','segment':self.segment})

    def current(self,observation_time=None):
        return self.observation_fix(observation_time)[0]

    def observation_fix(self,observation_time=None):
        # Return one fix/reason pair under the same lock; no later fix tags an older sighting.
        with self.lock:
            if not self.owner or not self.fix:
                return None,'unavailable'
            age=time.monotonic()-self.mono+self.fix['age_ms']/1000
            if age>self.ttl:return None,'stale'
            if self.fix['accuracy']>self.max_accuracy:return None,'inaccurate'
            if observation_time is not None and not 0<=observation_time-self.received<=self.ttl:
                return None,'unavailable'
            return {'lat':self.fix['lat'],'lon':self.fix['lon'],'accuracy_m':self.fix['accuracy'],
                    'source':'phone','segment':self.segment,'phone_timestamp_ms':self.fix['timestamp_ms'],
                    'received':self.received,'age_seconds':round(age,2)},'tagged'

    def status(self,owner=None,include_trail=False):
        with self.lock:
            age=time.monotonic()-self.mono+self.fix['age_ms']/1000 if self.fix else None
            valid=bool(self.owner and self.fix and age<=self.ttl and self.fix['accuracy']<=self.max_accuracy)
            return {'sharing':bool(self.owner),'mine':bool(owner and self.owner==owner),
                    'valid':valid,'age_seconds':round(age,1) if age is not None else None,
                    'accuracy_m':self.fix['accuracy'] if self.fix else None,
                    'speed_mps':self.fix.get('speed_mps') if self.fix else None,
                    'heading_deg':self.fix.get('heading_deg') if self.fix else None,
                    'max_accuracy_m':self.max_accuracy,'ttl_seconds':self.ttl,
                    'lat':self.fix['lat'] if self.fix else None,'lon':self.fix['lon'] if self.fix else None,
                    'trail':list(self.trail) if include_trail else []}


def nmea_rmc(fix):
    if not fix:
        body='GPRMC,,V,,,,,,,,,,N'
    else:
        stamp=datetime.fromtimestamp(fix['phone_timestamp_ms']/1000,timezone.utc)
        def coord(value,width):
            value=abs(value);degree=int(value);return ('%0*d%09.6f'%(width,degree,(value-degree)*60))
        body='GPRMC,%s,A,%s,%s,%s,%s,,,%s,,,A'%(stamp.strftime('%H%M%S.00'),coord(fix['lat'],2),
             'N' if fix['lat']>=0 else 'S',coord(fix['lon'],3),'E' if fix['lon']>=0 else 'W',stamp.strftime('%d%m%y'))
    checksum=0
    for byte in body.encode('ascii'):checksum^=byte
    return ('$%s*%02X\r\n'%(body,checksum)).encode('ascii')


class PhoneGPSBridge:
    def __init__(self,phone):
        self.phone=phone;self.status='Not sharing with gpsd';self.proc=None
        self.stop_event=threading.Event();self.thread=None;self.master=self.slave=None

    def start(self):
        if self.thread and self.thread.is_alive():return
        if not shutil.which('gpsd'):raise ValueError('gpsd is not installed. Phone location still works in PagerWatch.')
        try:
            connection=socket.create_connection(('127.0.0.1',2947),timeout=.5)
        except OSError:pass
        else:
            connection.close()
            raise ValueError('Another GPS service already uses port 2947. It was left running; phone GPS still works in PagerWatch.')
        self.stop_event.clear()
        self.master,self.slave=pty.openpty();tty.setraw(self.slave);os.set_blocking(self.master,False)
        try:
            self.proc=subprocess.Popen(['gpsd','-N','-n','-b','-S','2947',os.ttyname(self.slave)],
                                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        except Exception:
            os.close(self.master);os.close(self.slave);self.master=self.slave=None;raise
        self.status='Phone GPS shared on local gpsd :2947'
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()

    def run(self):
        try:
            while not self.stop_event.is_set():
                if self.proc.poll() is not None:
                    self.status='GPS bridge stopped; another service may own port 2947';return
                try:os.write(self.master,nmea_rmc(self.phone.current()))
                except BlockingIOError:pass
                self.stop_event.wait(1)
        except OSError as exc:self.status='GPS bridge error: '+str(exc)
        finally:
            if self.proc and self.proc.poll() is None:
                self.proc.terminate()
                try:self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:self.proc.kill();self.proc.wait(timeout=2)
            for fd in (self.master,self.slave):
                if fd is not None:os.close(fd)
            self.master=self.slave=None

    def stop(self):
        self.stop_event.set()
        if self.thread:self.thread.join(timeout=5)
        self.status='Not sharing with gpsd'
