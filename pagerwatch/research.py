# SPDX-License-Identifier: GPL-3.0-or-later
"""On-demand identification context, bounded exact-address history and evidence exports."""
import csv
from dataclasses import asdict
from datetime import datetime,timezone
import hashlib
from html import escape
import io
import json
import math
from pathlib import Path
import threading
import time
import zipfile
from urllib.parse import quote_plus
from .archive import SessionArchive,small_json
from . import __version__
from .detection import Observation
from .notebook import radio_key,reference_url
from .recovery import checkpoint_inventory

HISTORY_BYTES=8*1024*1024
FILE_BYTES=2*1024*1024
HISTORY_NOTE='Exact protocol/address matches only. Rotated addresses stay separate. Coordinates are receiver sighting locations, not transmitter positions. Missing history is inconclusive.'


def utc_stamp(value):
    try:return datetime.fromtimestamp(float(value),timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    except (ValueError,TypeError,OverflowError,OSError):return 'Unknown'


def device_record(device,notes=None):
    obs=device.obs;key=obs.protocol+':'+obs.address.upper();note=(notes or {}).get(key,{})
    return dict(obs.to_dict(),key=key,local_label=note.get('label',''),network_name=device.ap_name,
                first_seen=device.first_seen,last_seen=obs.timestamp,seen=device.seen,hits=[asdict(h) for h in device.hits],
                vendor=device.vendor,bluetooth=device.bluetooth,security=device.security,
                first_location=device.first_location,last_location=device.last_location,strongest_location=device.strongest_location)


def identification(row,detector=None):
    if not row:return dict(summary='No retained identification evidence',cautions=['Review the saved sightings and original logs.'],matches=[],references=[])
    matches=[];references=[];cautions=[]
    values={field:row[field] for field in Observation.__dataclass_fields__ if field in row}
    try:obs=Observation(**values)
    except TypeError:obs=None
    for hit in row.get('hits',[])[:20]:
        tests=[];rule=next((r for r in getattr(detector,'rules',[]) if r.get('id')==hit.get('rule')),None)
        if rule and obs:
            for condition in rule.get('conditions',[])[:12]:
                field=condition['field']
                observed=obs.manufacturer if field=='company' or field.startswith('company_payload:') else obs.uuids+list(obs.service_data) if field=='uuid' else obs.service_data if field.startswith('service_payload:') else dict(manufacturer=obs.manufacturer,service_data=obs.service_data) if field=='payload' else getattr(obs,field,'')
                tests.append(dict(field=field,op=condition['op'],expected=str(condition['value'])[:256],observed=str(observed)[:512],matched=bool(detector.matches(obs,condition))))
            if all(c['field']=='name' for c in rule.get('conditions',[])):cautions.append('Name-only rule: advertised names can be changed.')
            if all(c['field'] in ('name','company') for c in rule.get('conditions',[])):cautions.append('A company identifier is manufacturer context, not a confirmed device model.')
        elif str(hit.get('rule','')).startswith('watch-'):cautions.append('A local watchlist match is not a device-model identification.')
        source=hit.get('source','')
        try:source=reference_url(source)
        except ValueError:source=''
        if source and source not in references:references.append(source)
        matches.append(dict(rule_id=hit.get('rule',''),label=str(hit.get('label','Signature'))[:160],rank=hit.get('score'),evidence=str(hit.get('evidence',''))[:2000],source=source,tests=tests))
    if row.get('metadata_source') in ('bluez_cached_properties','hci_scan_cache'):cautions.append('Some metadata came from a scan cache rather than a fresh advertisement.')
    kind=row.get('address_type','')
    if row.get('protocol')=='ble' and 'random' in kind.lower():cautions.append('This Bluetooth address is marked random; it may change.')
    if row.get('protocol')=='wifi':
        try:
            if int(row.get('address','').split(':')[0],16)&2:cautions.append('Locally administered Wi-Fi address; a manufacturer prefix cannot establish device identity.')
        except ValueError:pass
    companies=[row.get('vendor',{}).get('name','')]+[v.get('name','') for v in row.get('bluetooth',{}).get('companies',[]) if isinstance(v,dict)]
    shortcuts=[dict(label='Research '+company+' documentation',url='https://duckduckgo.com/?q='+quote_plus(company+' official hardware documentation')) for company in list(dict.fromkeys(companies))[:4] if company and company not in ('Unknown','Unknown company')]
    if shortcuts:cautions.append('Manufacturer searches use company names only, open manually, and do not establish a device model.')
    cautions.append('Rule ranks are not identity probabilities. A match is not proof of an attack or an operator.')
    return dict(rules_version=getattr(detector,'version','unknown'),summary='Advertised identifiers matched '+str(len(matches))+' rule(s)' if matches else 'No device signature matched the observed metadata',
                vendor=row.get('vendor',{}),bluetooth=row.get('bluetooth',{}),shortcuts=shortcuts,matches=matches,references=references,cautions=list(dict.fromkeys(cautions)))


def _number(value):
    try:
        n=float(value);return n if math.isfinite(n) else None
    except (ValueError,TypeError):return None


def _fix(value):
    try:
        obj=json.loads(value) if isinstance(value,str) else value
        if not isinstance(obj,dict):return None
        lat,lon=_number(obj.get('lat')),_number(obj.get('lon'))
        return obj if lat is not None and lon is not None and -90<=lat<=90 and -180<=lon<=180 else None
    except (ValueError,TypeError):return None


def _inventory_row(row,key):
    try:found=radio_key(str(row.get('protocol'))+':'+str(row.get('address')))
    except ValueError:return None
    if found!=key:return None
    return dict(key=key,name=row.get('name',''),first_seen=_number(row.get('first_seen_unix')),last_seen=_number(row.get('last_seen_unix')),
                observations=_number(row.get('observations')),count_kind='inventory observations',
                first_location=_fix(row.get('first_location_json')),last_location=_fix(row.get('last_location_json')),strongest_location=_fix(row.get('strongest_location_json')),hits=[] if row.get('classification') in ('','Unclassified',None) else [dict(label=row.get('classification'),score=_number(row.get('rule_rank')),evidence=row.get('evidence',''),source='')])


def history_page(archive,key,offset=0,current=None):
    key=radio_key(key);listing=archive.listing(offset);matches=[];read=0;warnings=[];processed=0;limited=listing.get('limited',False)
    for run in listing['sessions']:
        if read>=HISTORY_BYTES:break
        ident=run['id'];folder=archive.directory(ident);match=None;partial=False
        if current and ident==current.get('session'):
            d=next((d for d in current.get('devices',[]) if d.get('key')==key),None)
            if d:match=dict(key=key,name=d.get('network_name') or d.get('name',''),first_seen=d.get('first_seen'),last_seen=d.get('last_seen'),observations=d.get('seen'),count_kind='live inventory observations',first_location=d.get('first_location'),last_location=d.get('last_location'),strongest_location=d.get('strongest_location'))
            # Capture the live journal offset to avoid reading newly appended data indefinitely.
            log_end=current.get('observation_bytes')
        else:log_end=None
        checkpoint=small_json(folder/'checkpoint.json')
        inventory=folder/'devices.csv' if (folder/'summary.json').is_file() else checkpoint_inventory(folder,checkpoint)
        if match is None and inventory and inventory.is_file() and not inventory.is_symlink():
            used=0;chunks=[]
            try:
                with inventory.open('rb') as stream:
                    
                    while used<FILE_BYTES and read<HISTORY_BYTES:
                        line=stream.readline(min(65537,FILE_BYTES-used,HISTORY_BYTES-read));used+=len(line);read+=len(line);chunks.append(line)
                        if not line:break
                        if len(line)>65536 or not line.endswith(b'\n'):partial=True;break
                        # Inventories are csv.writer output; quoted labels/names can contain newlines.
                        # Decode a bounded full CSV below instead of assuming line-aligned records.
                    partial=partial or stream.read(1)!=b''
                raw=b''.join(chunks)
                for row in csv.DictReader(io.StringIO(raw.decode('utf-8',errors='replace'))):
                    match=_inventory_row(row,key)
                    if match:break
            except (OSError,csv.Error):partial=True
        # Journals include evicted addresses. For interrupted inventories, append only
        # complete journal records after the checkpoint; counts remain explicitly mixed.
        journal=folder/'observations.jsonl';unfinished=not run.get('closed')
        if (match is None or unfinished) and journal.is_file() and not journal.is_symlink() and read<HISTORY_BYTES:
            begin=checkpoint.get('observation_bytes',0) if match and unfinished else 0
            if type(begin) is not int or begin<0:begin=0
            used=0;logged=0
            try:
                with journal.open('rb') as stream:
                    end=stream.seek(0,2);end=min(end,log_end) if type(log_end) is int and 0<=log_end<=end else end
                    if begin>end:begin=0;partial=True
                    stream.seek(begin)
                    while stream.tell()<end and used<FILE_BYTES and read<HISTORY_BYTES:
                        line=stream.readline(min(65537,end-stream.tell(),FILE_BYTES-used,HISTORY_BYTES-read));used+=len(line);read+=len(line)
                        if not line:break
                        if not line.endswith(b'\n') or len(line)>65536:partial=True;break
                        try:
                            row=json.loads(line);obs=row['observation']
                            if radio_key(str(obs.get('protocol'))+':'+str(obs.get('address')))!=key:continue
                            stamp=_number(obs.get('timestamp'))
                            if stamp is None:continue
                            logged+=1;fix=_fix(row.get('observer_location'))
                            if fix:fix=dict(fix,observed_at=stamp,rssi=obs.get('rssi'))
                            if match is None:match=dict(key=key,name=row.get('network_name') or obs.get('name',''),first_seen=stamp,last_seen=stamp,observations=0,count_kind='recorded journal sightings',hits=row.get('matches',[]),first_location=None,last_location=None,strongest_location=None)
                            if match.get('first_seen') is None or stamp<match['first_seen']:match['first_seen']=stamp
                            if match.get('last_seen') is None or stamp>=match['last_seen']:
                                match['last_seen']=stamp;match['name']=row.get('network_name') or obs.get('name') or match['name']
                                if fix:match['last_location']=fix
                            if fix:
                                first=match.get('first_location');latest=match.get('last_location')
                                if not first or stamp<(_number(first.get('observed_at')) or float('inf')):match['first_location']=fix
                                if not latest or stamp>=(_number(latest.get('observed_at')) or -1):match['last_location']=fix
                            previous=match.get('strongest_location');rssi=_number(obs.get('rssi'))
                            if fix and (not previous or (rssi is not None and (previous.get('rssi') is None or rssi>previous['rssi']))):match['strongest_location']=fix
                        except (ValueError,TypeError,KeyError,AttributeError):partial=True;continue
                    partial=partial or stream.tell()<end
                if match and logged:
                    if match['count_kind']=='recorded journal sightings':match['observations']=logged
                    elif match['count_kind']!='live inventory observations':match['count_kind']='checkpoint inventory + logged tail';match['logged_tail']=logged
            except OSError:partial=True
        if partial:warnings.append(ident+': read limit or incomplete/malformed data; history may omit sightings')
        if match:
            match.update(session=ident,session_label=run.get('label',''),partial=partial or bool(run.get('active')),active=bool(current and ident==current.get('session')))
            matches.append(match)
        processed+=1
    if processed<len(listing['sessions']):next_offset=offset+processed;limited=True
    else:next_offset=listing['next']
    return dict(key=key,matches=matches,scanned_runs=processed,offset=offset,next_offset=next_offset,bytes_read=read,
                limited=bool(limited or warnings),warnings=warnings,note=HISTORY_NOTE)


def research_document(archive,store,key,current,detector=None,offset=0):
    key=radio_key(key);row=next((d for d in current.get('devices',[]) if d.get('key')==key),None)
    history=history_page(archive,key,offset,current)
    if row is None and history['matches']:
        latest=max(history['matches'],key=lambda m:m.get('last_seen') or 0)
        row=dict(latest,protocol=key.split(':',1)[0],address=key.split(':',1)[1],metadata_source='saved_inventory')
    return dict(version=__version__,current_session=current.get('session'),key=key,device=row,identification=identification(row,detector),notebook=store.get(key),notebook_storage=store.status(),history=history,generated=time.time())


def evidence_bundle(document,store):
    notebook,photos=store.export(document['key']);document=dict(document,notebook=notebook)
    files={name:json.dumps(value,indent=2,ensure_ascii=True,allow_nan=False).encode() for name,value in
           (('context.json',{key:document.get(key) for key in ('version','generated','current_session','key')}),('device.json',document.get('device')),('identification.json',document['identification']),('notebook.json',notebook),('history.json',document['history']))}
    for photo,data in photos:files['attachments/'+photo['id']+'.'+photo['ext']]=data
    files['README.txt']=('PagerWatch device evidence bundle\nGenerated: '+str(document['generated'])+'\n\n'+HISTORY_NOTE+'\nThis bundle contains the requested history page, not every session or every raw observation.\nHistory read limits and source counts are recorded in history.json. Exports contain original identifiers and coordinates even in Privacy mode.\nNotes, photos and saved links are user annotations, not independently verified radio evidence.\nThe web uploader resizes/re-encodes photos; keep originals separately. Reference links are not fetched automatically.\nNotebook is current at export; radio data and history are snapshots. Raw radio journals remain available in session exports.\n').encode()
    e=lambda v:escape(str(v if v is not None else ''),quote=True)
    links=list(dict.fromkeys(document['identification'].get('references',[])+[r['url'] for r in document['identification'].get('shortcuts',[])]+notebook['links']))
    refs=''.join('<li><a rel="noreferrer noopener" href="'+e(reference_url(url))+'">'+e(url)+'</a></li>' for url in links)
    images=''.join('<figure><img width="600" src="attachments/'+p['id']+'.'+p['ext']+'"><figcaption>'+e(p['name'])+' (user attachment)</figcaption></figure>' for p,_ in photos)
    rows=''.join('<tr><td>'+e(m['session_label'] or m['session'])+'</td><td>'+e(utc_stamp(m.get('first_seen')))+'</td><td>'+e(utc_stamp(m.get('last_seen')))+'</td><td>'+e(m.get('observations'))+' '+e(m.get('count_kind'))+'</td><td>'+e(json.dumps(m.get('last_location')))+'</td></tr>' for m in document['history']['matches'])
    files['report.html']=('''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>PagerWatch evidence</title><style>body{font:16px/1.6 system-ui;max-width:1100px;margin:30px auto;padding:20px;background:#0b100e;color:#edf2e9}h1,h2,a{color:#c0f56b}pre{white-space:pre-wrap;overflow-wrap:anywhere}table{border-collapse:collapse}td,th{border:1px solid #344532;padding:10px;text-align:left;overflow-wrap:anywhere}img{max-width:100%;height:auto}.scroll{overflow:auto}</style><h1>PagerWatch research evidence</h1><p>'''+e(document['key'])+'</p><p>Generated: '+e(utc_stamp(document['generated']))+'</p><p>'+e(HISTORY_NOTE)+'</p><h2>Identification evidence</h2><pre>'+e(json.dumps(document['identification'],indent=2))+'</pre><h2>User research notes</h2><pre>'+e(notebook['notes'])+'</pre><h2>References (manual links)</h2><ul>'+refs+'</ul><h2>Recorded run history</h2><p>Requested history page only. Limited: '+e(document['history']['limited'])+'</p><div class="scroll"><table><tr><th>Run</th><th>First timestamp</th><th>Latest timestamp</th><th>Count / source</th><th>Latest receiver location</th></tr>'+rows+'</table></div><h2>User attachments</h2>'+images+'<p>Read README.txt for scope and limits. SHA256SUMS lists each included file.</p></html>').encode()
    files['SHA256SUMS']=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in sorted(files.items())).encode()
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=3) as archive:
        for name,data in files.items():archive.writestr(name,data)
    return out.getvalue()
