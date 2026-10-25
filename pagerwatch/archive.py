# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded session review. Only known session IDs and export filenames are readable."""
import csv
import json
import os
import math
from pathlib import Path
import re
import time
from .fieldtools import clean_text
from .recovery import checkpoint_inventory,recover_tail

SESSION_ID=re.compile(r'^\d{8}T\d{6}Z-[a-f0-9]{8}$')
FILES=('devices.csv','observations.jsonl','discoveries.jsonl','summary.json','scanner_status.json','checkpoint.json')

def small_json(path,limit=1024*1024):
    if path.is_symlink():return {}
    try:
        with path.open('rb') as stream:raw=stream.read(limit+1)
        if len(raw)>limit:return {}
        value=json.loads(raw)
        return value if isinstance(value,dict) else {}
    except (OSError,ValueError):return {}

class SessionArchive:
    def __init__(self,root):self.root=Path(root).resolve()
    def directory(self,ident):
        if not isinstance(ident,str) or not SESSION_ID.fullmatch(ident):raise ValueError('Invalid session ID')
        directory=self.root/ident
        if directory.is_symlink() or not directory.is_dir() or directory.resolve().parent!=self.root:raise ValueError('Session not found')
        return directory
    def file(self,ident,name):
        if name not in FILES:raise ValueError('Export not allowed')
        path=self.directory(ident)/name
        if path.is_symlink() or not path.is_file() or path.resolve().parent!=self.directory(ident):raise ValueError('Export unavailable')
        return path
    def listing(self,offset=0):
        if not isinstance(offset,int) or not 0<=offset<=5000:raise ValueError('Invalid session page')
        names=[];limited=False
        with os.scandir(self.root) as stream:
            for item in stream:
                if not SESSION_ID.fullmatch(item.name) or item.is_symlink() or not item.is_dir(follow_symlinks=False):continue
                if len(names)>=5000:limited=True;break
                names.append(item.name)
        names.sort(reverse=True);rows=[]
        for ident in names[offset:offset+25]:
            folder=self.directory(ident);summary=small_json(folder/'summary.json');closed=bool(summary);checkpoint=small_json(folder/'checkpoint.json');summary=summary or checkpoint;info=small_json(folder/'session-info.json',4096)
            size=0;available=[]
            with os.scandir(folder) as entries:
                for entry in entries:
                    if entry.is_file(follow_symlinks=False):size+=entry.stat(follow_symlinks=False).st_size
            available=[name for name in FILES if (folder/name).is_file() and not (folder/name).is_symlink()]
            rows.append({'id':ident,'label':str(info.get('label',''))[:80],'closed':closed,'checkpointed':checkpoint.get('checkpointed'),'started':summary.get('started'),
                         'observations':summary.get('observations_processed'),'devices':summary.get('addresses_retained'),
                         'bytes':size,'files':available})
        return {'sessions':rows,'offset':offset,'next':offset+25 if offset+25<len(names) else None,'limited':limited}
    def rename(self,ident,label):
        directory=self.directory(ident);label=clean_text(label)
        target=directory/'session-info.json';temporary=directory/'session-info.tmp'
        if temporary.is_symlink() or target.is_symlink():raise ValueError('Invalid session metadata')
        with temporary.open('w',encoding='utf-8') as stream:json.dump({'label':label},stream,ensure_ascii=True)
        temporary.chmod(0o600);temporary.replace(target)
    def review(self,ident):
        directory=self.directory(ident);summary=small_json(directory/'summary.json');info=small_json(directory/'session-info.json',4096)
        checkpoint=small_json(directory/'checkpoint.json') if not summary else {};interrupted=not bool(summary);summary=summary or checkpoint
        devices=[];truncated=False
        try:path=self.file(ident,'devices.csv')
        except ValueError:path=checkpoint_inventory(directory,checkpoint)
        if interrupted and checkpoint_inventory(directory,checkpoint):path=checkpoint_inventory(directory,checkpoint)
        if path:
            # Refuse unexpectedly huge inventories, never read radio logs into RAM.
            if path.stat().st_size>8*1024*1024:truncated=True
            else:
                with path.open(newline='',encoding='utf-8',errors='replace') as stream:
                    for row in csv.DictReader(stream):
                        if len(devices)>=2000:truncated=True;break
                        protocol=row.get('protocol','');address=row.get('address','').upper()
                        if protocol not in ('wifi','ble') or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}',address):continue
                        def number(key):
                            try:
                                value=float(row[key]);return value if math.isfinite(value) else None
                            except (ValueError,KeyError,TypeError):return None
                        def obj(key):
                            try:value=json.loads(row.get(key,'null'));return value if isinstance(value,dict) else None
                            except (ValueError,TypeError):return None
                        classification=row.get('classification','Unclassified')
                        hits=[] if classification=='Unclassified' else [{'label':classification,'score':number('rule_rank'),'evidence':row.get('evidence',''),'source':''}]
                        devices.append({'key':protocol+':'+address,'protocol':protocol,'address':address,'name':row.get('name',''),'network_name':'',
                                        'local_label':row.get('local_label',''),'bookmarked':row.get('bookmarked','')=='True','known':row.get('known','')=='True',
                                        'rssi':number('last_rssi_dbm'),'last_rssi':number('last_rssi_dbm'),'seen':number('observations'),
                                        'last_seen':number('last_seen_unix'),'hits':hits,'security':obj('security_json') or {},
                                        'first_location':obj('first_location_json'),'last_location':obj('last_location_json'),'strongest_location':obj('strongest_location_json')})
        recovery=None
        if interrupted:
            devices,recovery=recover_tail(directory,checkpoint,devices)
            recovery.update(interrupted=True,checkpointed=checkpoint.get('checkpointed'),summary_as_of_checkpoint=bool(checkpoint))
        field=summary.get('field_summary')
        if not isinstance(field,dict):
            total=summary.get('observations_processed');located=summary.get('geotagged_observations')
            start=summary.get('started');end=summary.get('ended')
            field={'duration_seconds':max(0,end-start) if isinstance(start,(int,float)) and isinstance(end,(int,float)) else None,
                   'observations':total,'geotagged_observations':located,
                   'gps_coverage_percent':round(100*located/total,1) if isinstance(total,(int,float)) and total>0 and isinstance(located,(int,float)) else None,
                   'retained_wifi':sum(d['protocol']=='wifi' for d in devices) if not truncated else None,
                   'retained_ble':sum(d['protocol']=='ble' for d in devices) if not truncated else None,'alerted_addresses':None}
        return {'recovery':recovery,'field_summary':field,'geotagged_observations':summary.get('geotagged_observations'), 'session':ident,'session_label':str(info.get('label',''))[:80],'version':summary.get('version',''),
                'started':summary.get('started'),'now':summary.get('ended',time.time()),'processed':summary.get('observations_processed',0),
                'devices':devices,'truncated':truncated,'files':[name for name in FILES if (directory/name).is_file() and not (directory/name).is_symlink()],
                'scanners':{},'coverage':{},'log_error':summary.get('log_error',''),'evicted':summary.get('evictions',0),
                'geotagged_devices':sum(bool(d['last_location']) for d in devices)}
