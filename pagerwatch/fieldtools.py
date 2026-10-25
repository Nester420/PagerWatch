# SPDX-License-Identifier: GPL-3.0-or-later
"""Validated local labels, watch rules, profiles and low-cost field health."""
import math
import re
import secrets
import shutil
import time
from .detection import Hit,uuid128

PROFILES=('survey','track','quiet')
KEY=re.compile(r'^(wifi|ble):(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')

def clean_text(value,limit=80):
    if not isinstance(value,str) or len(value)>limit or any(ord(c)<32 or ord(c)==127 for c in value):raise ValueError('Use plain text up to %d characters'%limit)
    return value.strip()

def validate_note(value):
    if not isinstance(value,dict) or not KEY.fullmatch(str(value.get('key',''))):raise ValueError('Select a radio address')
    if not isinstance(value.get('bookmark',False),bool):raise ValueError('Invalid bookmark')
    if not isinstance(value.get('known',False),bool):raise ValueError('Invalid known-device flag')
    return {'known':value.get('known',False),'key':value['key'].split(':',1)[0]+':'+value['key'].split(':',1)[1].upper(),'label':clean_text(value.get('label','')),'bookmark':value.get('bookmark',False)}

def validate_rule(value):
    if not isinstance(value,dict):raise ValueError('Invalid watch rule')
    ident=value.get('id','')
    if not isinstance(ident,str) or (ident and not re.fullmatch('[a-f0-9]{12}',ident)):raise ValueError('Invalid watch rule ID')
    if value.get('delete') is True:
        if not ident:raise ValueError('Choose a watch rule')
        return {'id':ident,'delete':True}
    kind=value.get('kind');target=value.get('target','')
    if kind=='address':target=validate_note({'key':target})['key']
    elif kind=='uuid':
        if not isinstance(target,str) or not re.fullmatch(r'(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})',target):raise ValueError('Use a 16-bit or full service UUID')
        target=uuid128(target)
    else:raise ValueError('Watch by address or service UUID')
    minimum=value.get('min_rssi')
    if minimum is not None and (isinstance(minimum,bool) or not isinstance(minimum,int) or not -127<=minimum<=0):raise ValueError('Minimum RSSI must be -127..0 or blank')
    enabled=value.get('enabled',True)
    if not isinstance(enabled,bool):raise ValueError('Invalid watch rule state')
    return {'id':ident or secrets.token_hex(6),'kind':kind,'target':target,'label':clean_text(value.get('label','Watchlist match')) or 'Watchlist match','min_rssi':minimum,'enabled':enabled}

def apply_note(config,value):
    value=validate_note(value);notes=dict(config.get('device_notes',{}))
    if value['key'] not in notes and len(notes)>=2000:raise ValueError('Local label limit reached (2000)')
    if value['label'] or value['bookmark'] or value['known']:notes[value['key']]={k:value[k] for k in ('label','bookmark','known')}
    else:notes.pop(value['key'],None)
    config['device_notes']=notes

def apply_rule(config,value):
    value=validate_rule(value);rules=list(config.get('watch_rules',[]));rules=[r for r in rules if r.get('id')!=value['id']]
    if not value.get('delete'):
        if len(rules)>=64:raise ValueError('Watchlist limit reached (64)')
        rules.append(value)
    config['watch_rules']=rules

def watch_hits(config,obs):
    rules=config.get('watch_rules',[])[:64]
    if not rules:return []
    hits=[];key=obs.protocol+':'+obs.address.upper()
    services={uuid128(u) for u in obs.uuids+list(obs.service_data)} if obs.protocol=='ble' else set()
    for rule in rules:
        if not rule.get('enabled',True):continue
        matches=rule.get('target')==key if rule.get('kind')=='address' else rule.get('target') in services
        minimum=rule.get('min_rssi')
        if matches and (minimum is None or (obs.rssi is not None and obs.rssi>=minimum)):
            hits.append(Hit('watch-'+rule['id'],rule['label'],'WATCHLIST',100,'Local exact '+rule['kind']+' rule'+(' at RSSI >= %d dBm'%minimum if minimum is not None else ''),'local:watchlist'))
    return hits

def gps_health(gps):
    if gps.get('valid'):return 'FRESH FIX'
    if not gps.get('sharing'):return 'GPS OFF'
    if gps.get('age_seconds') is not None and gps['age_seconds']>gps.get('ttl_seconds',15):return 'STALE FIX — sightings not geotagged'
    if gps.get('accuracy_m') is not None and gps['accuracy_m']>gps.get('max_accuracy_m',100):return 'LOW ACCURACY — sightings not geotagged'
    return 'WAITING FOR FIX — sightings not geotagged'

class StorageHealth:
    def __init__(self):self.next_read=0;self.disk={}
    def snapshot(self,session):
        now=time.monotonic()
        if now>=self.next_read:
            self.next_read=now+10
            try:
                disk=shutil.disk_usage(session.path);self.disk={'free_bytes':disk.free,'total_bytes':disk.total}
            except OSError:self.disk={'error':'Storage unavailable'}
        result=dict(self.disk,observation_bytes=session.bytes_written,discovery_bytes=session.discovery_bytes,limit_bytes=session.log_limit)
        warnings=[]
        if result.get('error'):warnings.append(result['error'])
        if session.log_error:warnings.append(session.log_error)
        if session.discovery_error:warnings.append(session.discovery_error)
        if result.get('free_bytes',math.inf)<50*1024*1024:warnings.append('Less than 50 MB free')
        if max(session.bytes_written,session.discovery_bytes)>=session.log_limit*.9:warnings.append('Session journal at or above 90% of limit')
        result['warnings']=warnings;return result
