# SPDX-License-Identifier: GPL-3.0-or-later
"""Atomic checkpoints and bounded, read-only recovery of interrupted sessions."""
import json
import errno
import os
from pathlib import Path
import re
import tempfile

def atomic_json(path,value):
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(mode='w',encoding='utf-8',dir=path.parent,delete=False) as stream:
            temporary=Path(stream.name);os.chmod(temporary,0o600);json.dump(value,stream,ensure_ascii=True);stream.flush();os.fsync(stream.fileno())
        temporary.replace(path)
        # Persist directory entries for both inventory rename and manifest commit.
        descriptor=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
        try:
            try:os.fsync(descriptor)
            except OSError as exc:
                if exc.errno not in (errno.EINVAL,errno.ENOTSUP):raise
        finally:os.close(descriptor)
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()

def checkpoint_inventory(directory,checkpoint):
    name=checkpoint.get('inventory','')
    if name not in ('devices-checkpoint-0.csv','devices-checkpoint-1.csv'):return None
    path=directory/name
    if path.is_symlink() or not path.is_file() or path.resolve().parent!=directory.resolve():return None
    return path

def recover_tail(directory,checkpoint,devices,limit=4*1024*1024):
    result={d['key']:d for d in devices};count=bad=0;limited=False
    path=directory/'observations.jsonl'
    if path.is_symlink() or not path.is_file():return devices,{'records':0,'skipped':0,'limited':False}
    size=path.stat().st_size;offset=checkpoint.get('observation_bytes',0)
    if type(offset) is not int or not 0<=offset<=size:offset=0
    with path.open('rb') as stream:
        stream.seek(offset);read=0
        while read<limit and count+bad<10000:
            line=stream.readline(min(65537,limit-read));read+=len(line)
            if not line:break
            if not line.endswith(b'\n'):
                bad+=1;limited=stream.tell()<size;break
            try:
                row=json.loads(line);o=row['observation'];protocol=o['protocol'];address=o['address'].upper()
                if protocol not in ('wifi','ble') or not re.fullmatch(r'(?:[0-9A-F]{2}:){5}[0-9A-F]{2}',address):raise ValueError()
                key=protocol+':'+address
                existing=result.get(key,{})
                if isinstance(existing.get('last_seen'),(int,float)) and isinstance(o.get('timestamp'),(int,float)) and o['timestamp']<=existing['last_seen']:
                    count+=1;continue
                old=result.pop(key,{})
                note=row.get('local_note') or {};fix=row.get('observer_location')
                if not isinstance(fix,dict):fix=None
                if fix:fix=dict(fix,observed_at=o.get('timestamp'),rssi=o.get('rssi'))
                item=dict(old,key=key,protocol=protocol,address=address,name=row.get('network_name') or o.get('name','') or old.get('name',''),
                          network_name=row.get('network_name') or old.get('network_name',''),local_label=note.get('label',old.get('local_label','')),
                          bookmarked=note.get('bookmark',old.get('bookmarked',False)),known=note.get('known',old.get('known',False)),rssi=o.get('rssi'),last_rssi=o.get('rssi'),
                          last_seen=o.get('timestamp'),seen=(old.get('seen') or 0)+1,hits=row.get('matches') or old.get('hits',[]),
                          security=row.get('security') or old.get('security',{}),first_location=old.get('first_location') or fix,
                          last_location=fix or old.get('last_location'),strongest_location=old.get('strongest_location'))
                previous=item.get('strongest_location')
                if fix and (not previous or (isinstance(o.get('rssi'),(int,float)) and o['rssi']>(previous.get('rssi') if isinstance(previous.get('rssi'),(int,float)) else -999))):item['strongest_location']=fix
                result[key]=item
                if len(result)>2000:result.pop(next(iter(result)))
                count+=1
            except (ValueError,TypeError,KeyError,AttributeError):bad+=1
        limited=limited or stream.tell()<size
    return list(result.values()),{'records':count,'skipped':bad,'limited':limited}
