# SPDX-License-Identifier: GPL-3.0-or-later
"""Portable settings backups; connection paths, certificates and logs stay local."""
import json
import math
import os
from pathlib import Path
import re
import tempfile
from .fieldtools import validate_note, validate_rule, PROFILES

MAX_BACKUP_BYTES=2*1024*1024
BOOLS=('wifi_enabled','ble_enabled','gps_enabled','ble_info_lookup','vibrate','privacy_mode')
INTS={'max_devices':(1,10000),'max_log_mb':(1,1000),'alert_threshold':(0,100)}
ENUMS={'wifi_scan_mode':('dual','2.4','5','current','custom'),'ble_backend':('auto','bluez','hcitool'),'scan_profile':PROFILES}
KEYS=set(BOOLS)|set(INTS)|set(ENUMS)|{'wifi_interface','ble_controller','ble_hci_interface','hop_frequencies','hop_seconds','exclude_addresses','device_notes','watch_rules'}

def validate_backup(document):
    if not isinstance(document,dict) or set(document)!={'format','schema','settings'} or document.get('format')!='pagerwatch-config' or type(document.get('schema')) is not int or document['schema'] not in (1,2):
        raise ValueError('Choose a PagerWatch configuration backup (schema 1 or 2)')
    value=document['settings']
    if not isinstance(value,dict) or set(value)!=KEYS:raise ValueError('Backup settings are missing or unsupported')
    result={}
    for key in BOOLS:
        if type(value[key]) is not bool:raise ValueError('Invalid '+key)
        result[key]=value[key]
    for key,(low,high) in INTS.items():
        if type(value[key]) is not int or not low<=value[key]<=high:raise ValueError('Invalid '+key)
        result[key]=value[key]
    for key,choices in ENUMS.items():
        if value[key] not in choices:raise ValueError('Invalid '+key)
        result[key]=value[key]
    for key in ('wifi_interface','ble_controller','ble_hci_interface'):
        item=value[key]
        if not isinstance(item,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{0,32}',item) or (key=='wifi_interface' and not item):raise ValueError('Invalid '+key)
        result[key]=item
    frequencies=value['hop_frequencies'];seconds=value['hop_seconds']
    if not isinstance(frequencies,list) or not 1<=len(frequencies)<=256 or any(type(f) is not int or not 2300<=f<=7125 for f in frequencies):raise ValueError('Invalid channel list')
    if isinstance(seconds,bool) or not isinstance(seconds,(int,float)) or not math.isfinite(seconds) or not .1<=seconds<=60:raise ValueError('Invalid hop interval')
    result.update(hop_frequencies=list(frequencies),hop_seconds=seconds)
    excluded=value['exclude_addresses']
    if not isinstance(excluded,list) or len(excluded)>10000 or any(not isinstance(a,str) or not re.fullmatch(r'(?:(?:wifi|ble):)?(?:[A-Fa-f0-9]{2}:){5}[A-Fa-f0-9]{2}',a,re.I) for a in excluded):raise ValueError('Invalid excluded addresses')
    result['exclude_addresses']=list(dict.fromkeys(a.upper() for a in excluded))
    notes=value['device_notes'];rules=value['watch_rules']
    if not isinstance(notes,dict) or len(notes)>2000:raise ValueError('Invalid local labels')
    result['device_notes']={}
    for key,note in notes.items():
        if not isinstance(note,dict) or set(note)-{'label','bookmark','known'}:raise ValueError('Invalid local label')
        clean=validate_note(dict(note,key=key))
        if clean['key'] in result['device_notes']:raise ValueError('Duplicate label address')
        result['device_notes'][clean['key']]={k:clean[k] for k in ('label','bookmark','known')}
    if not isinstance(rules,list) or len(rules)>64:raise ValueError('Invalid watchlist')
    result['watch_rules']=[];ids=set()
    for rule in rules:
        if not isinstance(rule,dict) or set(rule)-{'id','kind','target','label','min_rssi','enabled'} or not rule.get('id'):raise ValueError('Invalid watch rule')
        clean=validate_rule(rule)
        if clean['id'] in ids:raise ValueError('Duplicate watch rule ID')
        ids.add(clean['id']);result['watch_rules'].append(clean)
    return result

def backup_document(config):
    document={'format':'pagerwatch-config','schema':2,'settings':{k:config[k] for k in KEYS}}
    document['settings']=validate_backup(document)
    return document

def backup_preview(settings):
    return {'labels':len(settings['device_notes']),'watch_rules':len(settings['watch_rules']),
            'excluded':len(settings['exclude_addresses']),'profile':settings['scan_profile'],
            'settings':{k:v for k,v in settings.items() if k not in ('device_notes','watch_rules','exclude_addresses')}}

def pending_path(config_path):
    path=Path(config_path)
    return path.parent/'.state'/(path.name+'.restore.json')

def read_pending(config_path):
    path=pending_path(config_path)
    if path.parent.is_symlink() or path.is_symlink():raise ValueError('Invalid pending configuration path')
    if not path.exists():return None
    with path.open('rb') as stream:raw=stream.read(MAX_BACKUP_BYTES+1)
    if len(raw)>MAX_BACKUP_BYTES:raise ValueError('Configuration backup is too large')
    return validate_backup(json.loads(raw))

def stage_restore(config_path,document):
    settings=validate_backup(document);path=pending_path(config_path)
    if path.parent.is_symlink() or path.is_symlink():raise ValueError('Invalid pending configuration path')
    path.parent.mkdir(mode=0o700,exist_ok=True)
    raw=json.dumps({'format':'pagerwatch-config','schema':2,'settings':settings},ensure_ascii=False).encode('utf-8')
    if len(raw)>MAX_BACKUP_BYTES:raise ValueError('Configuration backup is too large')
    temporary=None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent,delete=False) as stream:
            temporary=Path(stream.name);os.chmod(temporary,0o600);stream.write(raw);stream.flush();os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():temporary.unlink()
