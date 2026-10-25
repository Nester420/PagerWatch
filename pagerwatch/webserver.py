# SPDX-License-Identifier: GPL-3.0-or-later
"""Local HTTPS companion. HTTP threads consume snapshots; controls run on the scanner thread."""
from collections import OrderedDict, deque
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
import csv
import hashlib
import io
import ipaddress
import re
import json
import queue
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit
from .phonegps import PhoneGPS, PhoneGPSBridge
from .notebook import ResearchStore,NotebookConflict
from .research import research_document,evidence_bundle
from .notebook import ResearchStore,NotebookConflict
from .research import research_document,evidence_bundle
from .sessiontools import compare_sessions,deletion_preview,DeletionTickets
from .reporting import render_report
from .fieldtools import validate_note,validate_rule,clean_text,gps_health
from .archive import SessionArchive,SESSION_ID,small_json
from .config_backup import MAX_BACKUP_BYTES,backup_document,validate_backup,backup_preview


class WebService:
    def __init__(self,root,config,certificate_helper=None):
        self.root=Path(root);self.config=config;self.restore_pending=False
        self.bind=str(config.get('web_bind','172.16.52.1'))
        ipaddress.ip_address(self.bind)
        if self.bind in ('0.0.0.0','::'):raise ValueError('Choose a management IP, not every interface')
        self.port=int(config.get('web_port',8443))
        if not 0<=self.port<=65535:raise ValueError('Invalid web port')
        self.helper=certificate_helper or self.root/'lib/pw-certgen-mipsle'
        self.research_store=ResearchStore(self.root/".state/research");self.detector=None;self.research_gate=threading.BoundedSemaphore(1)
        self.research_store=ResearchStore(self.root/".state/research");self.detector=None;self.research_gate=threading.BoundedSemaphore(1)
        self.deletions=DeletionTickets()
        self.phone=PhoneGPS();self.bridge=PhoneGPSBridge(self.phone)
        self.lock=threading.Lock();self.state={};self.sessions=OrderedDict();self.attempts=OrderedDict()
        self.commands=queue.Queue(maxsize=32);self.results=deque(maxlen=32)
        self.points=deque(maxlen=5000);self.point_times=OrderedDict()
        self.status='Starting HTTPS';self.pin='';self.fingerprint='';self.url='';self.server=None;self.thread=None
        self.archive=None;self.discovery_path=None;self.discovery_bytes=0;
        self.log_path=None;self.log_bytes=0;self.report_path=None;self.last_request=0;self.rotate_pin()

    def rotate_pin(self):
        with self.lock:
            self.pin='%06d'%secrets.randbelow(1000000)
            self.sessions.clear()
            # An existing phone must explicitly start again with its new session.
            with self.phone.lock:self.phone.owner=None;self.phone.fix=None
        state=self.root/'.state'
        state.mkdir(mode=0o700,exist_ok=True)
        target=state/'web-access.txt';target.write_text(self.pin+'\n');target.chmod(0o600)

    def certificates(self):
        target=self.root/'.state/tls'
        if not (target/'server.pem').exists() or (target/'host.txt').read_text().strip()!=self.bind:
            temporary=Path(tempfile.mkdtemp(prefix='tls-',dir=str(target.parent)))
            try:
                helper=Path(self.helper)
                helper.chmod(helper.stat().st_mode | 0o100)
                subprocess.run([str(helper),str(temporary),self.bind],check=True,timeout=40,
                               stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                if target.exists():shutil.rmtree(target)
                temporary.rename(target)
            finally:
                if temporary.exists():shutil.rmtree(temporary)
        import ssl
        der=ssl.PEM_cert_to_DER_cert((target/'ca.pem').read_text())
        self.fingerprint=hashlib.sha256(der).hexdigest().upper()
        return target

    def start(self):
        try:
            import ssl
            certs=self.certificates()
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(certs/'server.pem'),str(certs/'server-key.pem'))
            service=self
            class Server(ThreadingHTTPServer):
                daemon_threads=True;allow_reuse_address=True
                slots=threading.BoundedSemaphore(8)
                def get_request(self):
                    connection,address=super().get_request();connection.settimeout(5)
                    try:connection=context.wrap_socket(connection,server_side=True)
                    except Exception:connection.close();raise
                    return connection,address
                def process_request(self,request,address):
                    if not self.slots.acquire(False):request.close();return
                    try:super().process_request(request,address)
                    except Exception:self.slots.release();raise
                def process_request_thread(self,request,address):
                    try:super().process_request_thread(request,address)
                    finally:self.slots.release()
            class Handler(BaseHTTPRequestHandler):
                def log_message(self,*_):pass
                def do_GET(self):service.handle(self,False)
                def do_POST(self):service.handle(self,True)
            self.server=Server((self.bind,self.port),Handler)
            self.port=self.server.server_address[1];self.url='https://%s:%d'%(self.bind,self.port)
            self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
            self.status='HTTPS ready'
        except Exception as exc:
            self.status='Web unavailable: '+str(exc)
            if self.server:self.server.server_close();self.server=None

    def stop(self):
        self.bridge.stop()
        if self.server:self.server.shutdown();self.server.server_close()
        if self.thread:self.thread.join(timeout=3)
        self.status='Stopped'

    def login(self,ip,pin):
        now=time.monotonic()
        with self.lock:
            attempts=[t for t in self.attempts.get(ip,[]) if now-t<60]
            if len(attempts)>=5:return None,429
            attempts.append(now);self.attempts[ip]=attempts;self.attempts.move_to_end(ip)
            while len(self.attempts)>64:self.attempts.popitem(last=False)
            if not isinstance(pin,str) or not secrets.compare_digest(pin,self.pin):return None,403
            token=secrets.token_urlsafe(32);self.sessions[token]=now
            while len(self.sessions)>8:self.sessions.popitem(last=False)
            return token,200

    def owner(self,handler):
        try:
            cookie=SimpleCookie();cookie.load(handler.headers.get('Cookie',''));token=cookie['pw_session'].value
        except Exception:return None
        with self.lock:
            stamp=self.sessions.get(token)
            if stamp is not None and time.monotonic()-stamp<12*3600:return token
        return None

    def response(self,h,status,body,kind='application/json',headers=None):
        if not isinstance(body,bytes):body=json.dumps(body,allow_nan=False,separators=(',',':')).encode()
        h.send_response(status);h.send_header('Content-Type',kind);h.send_header('Content-Length',str(len(body)))
        h.send_header('Cache-Control','no-store');h.send_header('X-Content-Type-Options','nosniff')
        security={'Referrer-Policy':'no-referrer',
                  'Content-Security-Policy':"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
                  'Permissions-Policy':'geolocation=(self)'}
        security.update(headers or {})
        for key,value in security.items():h.send_header(key,value)
        h.end_headers()
        try:h.wfile.write(body)
        except (OSError,TimeoutError):pass

    def handle(self,h,post):
        path=h.path.split('?',1)[0]
        expected='%s:%d'%(self.bind,self.port)
        if h.headers.get('Host')!=expected:
            self.response(h,403,{'error':'Unexpected host'});return
        owner=self.owner(h)
        try:
            if post:
                if h.headers.get('Origin')!=self.url or h.headers.get('X-PagerWatch')!='1':
                    self.response(h,403,{'error':'Open controls from the PagerWatch dashboard'});return
                length=int(h.headers.get('Content-Length','0'))
                limit=MAX_BACKUP_BYTES if path in ('/api/config/validate','/api/config/restore') and owner else 8192
                if owner and path=='/api/research/photo':limit=3*1024*1024
                if owner and path=='/api/research/note':limit=65536
                if owner and path=='/api/research/photo':limit=3*1024*1024
                if owner and path=='/api/research/note':limit=65536
                if not 0<length<=limit or h.headers.get('Content-Type','').split(';')[0]!='application/json':
                    self.response(h,413,{'error':'Expected a small JSON request'});return
                data=json.loads(h.rfile.read(length),parse_constant=lambda _:(_ for _ in ()).throw(ValueError('Nonfinite JSON')))
                if not isinstance(data,dict):raise ValueError('Expected a JSON object')
                if path=='/api/login':
                    token,status=self.login(h.client_address[0],data.get('pin'))
                    self.response(h,status,{'ok':bool(token),'error':'' if token else 'Too many attempts. Wait one minute.' if status==429 else 'Incorrect access code'},
                        headers={'Set-Cookie':'pw_session=%s; Path=/; HttpOnly; Secure; SameSite=Strict'%token} if token else None);return
                if not owner:self.response(h,401,{'error':'Enter the access code from the Pager WEB tab'});return
                if path=='/api/research/note':
                    value=self.research_store.save(data.get('key'),data.get('notes'),data.get('links'),data.get('revision'))
                    self.response(h,200,{'notebook':value,'storage':self.research_store.status()});return
                if path=='/api/research/photo':
                    value=self.research_store.add_photo(data.get('key'),data.get('data'),data.get('name'),data.get('revision'))
                    self.response(h,200,{'notebook':value,'storage':self.research_store.status()});return
                if path=='/api/research/photo/remove':
                    value=self.research_store.remove_photo(data.get('key'),data.get('id'),data.get('revision'))
                    self.response(h,200,{'notebook':value,'storage':self.research_store.status()});return
                if path=='/api/research/note':
                    value=self.research_store.save(data.get('key'),data.get('notes'),data.get('links'),data.get('revision'))
                    self.response(h,200,{'notebook':value});return
                if path=='/api/research/photo':
                    value=self.research_store.add_photo(data.get('key'),data.get('data'),data.get('name'),data.get('revision'))
                    self.response(h,200,{'notebook':value});return
                if path=='/api/research/photo/remove':
                    value=self.research_store.remove_photo(data.get('key'),data.get('id'),data.get('revision'))
                    self.response(h,200,{'notebook':value});return
                if path=='/api/archive/delete/preview':
                    if not self.archive:raise ValueError('Session library not ready')
                    with self.lock:active=self.state.get('session')
                    manifests=deletion_preview(self.archive,data.get('sessions'),active)
                    self.response(h,200,self.deletions.prepare(owner,manifests));return
                if path=='/api/archive/delete/confirm':
                    if data.get('confirmed') is not True:raise ValueError('Confirm permanent deletion first')
                    try:ident=self.deletions.queue(owner,data.get('token'),self.commands)
                    except queue.Full:self.response(h,503,{'error':'Controls busy. Try again.'});return
                    self.response(h,202,{'id':ident,'ok':True});return
                if path in ('/api/config/validate','/api/config/restore'):
                    settings=validate_backup(data)
                    if path.endswith('/validate'):
                        self.response(h,200,{'ok':True,'preview':backup_preview(settings)});return
                    ident=secrets.token_hex(6)
                    try:self.commands.put_nowait({'id':ident,'action':'config_restore','value':{'format':'pagerwatch-config','schema':2,'settings':settings}})
                    except queue.Full:self.response(h,503,{'error':'Controls busy. Try again.'});return
                    self.response(h,202,{'id':ident,'ok':True});return
                if path=='/api/gps/start':self.phone.start(owner)
                elif path=='/api/gps/update':self.phone.submit(owner,data)
                elif path=='/api/gps/stop':self.phone.stop(owner)
                elif path=='/api/control':
                    action=data.get('action');value=data.get('value')
                    choices={'wifi_mode':('dual','2.4','5','current'),'ble_backend':('auto','hcitool','bluez'),
                             'diagnostics':(None,), 'gps_bridge':(True,False), 'wifi_refresh':(None,),
                             'profile':('survey','track','quiet'),'privacy':(True,False)}
                    with self.lock: adapters=self.state.get('wifi_adapters',{}).get('interfaces',[])
                    choices['wifi_interface']=('auto','usb','adaptive')+tuple(row['name'] for row in adapters if row.get('type') in ('monitor','managed') and not row.get('owned'))
                    if action=='privacy':
                        if not isinstance(value,bool):raise ValueError('Invalid privacy setting')
                    elif action=='device_note':value=validate_note(value)
                    elif action=='watch_rule':value=validate_rule(value)
                    elif action=='session_rename':
                        if not isinstance(value,dict) or not SESSION_ID.fullmatch(str(value.get('id',''))):raise ValueError('Invalid session ID')
                        value={'id':value['id'],'label':clean_text(value.get('label',''))}
                    elif action=='track_target':
                        with self.lock:keys={d['key'] for d in self.state.get('devices',[])}
                        if value is not None and (not isinstance(value,str) or value not in keys):raise ValueError('Select a retained device')
                    elif action not in choices or value not in choices[action]:raise ValueError('Invalid control')
                    ident=secrets.token_hex(6)
                    try:self.commands.put_nowait({'id':ident,'action':action,'value':value})
                    except queue.Full:self.response(h,503,{'error':'Controls busy. Try again.'});return
                    self.response(h,202,{'id':ident,'ok':True});return
                else:self.response(h,404,{'error':'Unknown endpoint'});return
                self.response(h,200,{'ok':True,'gps':self.phone.status(owner)});return
            assets={'/':('web/index.html','text/html; charset=utf-8'),'/app.js':('web/app.js','text/javascript'),
                    '/style.css':('web/style.css','text/css'),'/logo.png':('assets/startup.png','image/png'),
                    '/ca.crt':('.state/tls/ca.pem','application/x-x509-ca-cert')}
            if path in assets:
                file,kind=assets[path];self.response(h,200,(self.root/file).read_bytes(),kind);return
            if not owner:self.response(h,401,{'error':'Enter the access code from the Pager WEB tab'});return
            if path=='/download/research/photo':
                query=parse_qs(urlsplit(h.path).query)
                photo,body=self.research_store.photo(query.get('key',[''])[0],query.get('id',[''])[0])
                self.response(h,200,body,photo['mime'],{'Content-Disposition':'inline; filename="photo-'+photo['id']+'.'+photo['ext']+'"'});return
            if path in ('/api/research/device','/download/evidence.zip'):
                if not self.archive:raise ValueError('Session library not ready')
                if not self.research_gate.acquire(False):self.response(h,503,{'error':'Research busy. Try again shortly.'});return
                try:
                    query=parse_qs(urlsplit(h.path).query)
                    with self.lock:current=self.state
                    doc=research_document(self.archive,self.research_store,query.get('key',[''])[0],current,self.detector,int(query.get('offset',['0'])[0]))
                    if path=='/download/evidence.zip':
                        body=evidence_bundle(doc,self.research_store)
                        self.response(h,200,body,'application/zip',{'Content-Disposition':'attachment; filename="PagerWatch-evidence.zip"'})
                    else:self.response(h,200,doc)
                finally:self.research_gate.release()
                return
            if path=='/download/research/photo':
                query=parse_qs(urlsplit(h.path).query)
                photo,body=self.research_store.photo(query.get('key',[''])[0],query.get('id',[''])[0])
                self.response(h,200,body,photo['mime'],{'Content-Disposition':'inline; filename="photo-'+photo['id']+'.'+photo['ext']+'"'});return
            if path in ('/api/research/device','/download/evidence.zip'):
                if not self.archive:raise ValueError('Session library not ready')
                if not self.research_gate.acquire(False):self.response(h,503,{'error':'Research busy. Try again shortly.'});return
                try:
                    query=parse_qs(urlsplit(h.path).query)
                    with self.lock:current=self.state
                    doc=research_document(self.archive,self.research_store,query.get('key',[''])[0],current,self.detector,int(query.get('offset',['0'])[0]))
                    if path=='/download/evidence.zip':
                        body=evidence_bundle(doc,self.research_store)
                        self.response(h,200,body,'application/zip',{'Content-Disposition':'attachment; filename="PagerWatch-evidence.zip"'})
                    else:self.response(h,200,doc)
                finally:self.research_gate.release()
                return
            if path=='/download/config-backup.json':
                body=json.dumps(backup_document(self.config),indent=2,ensure_ascii=False).encode('utf-8')
                self.response(h,200,body,'application/json',{'Content-Disposition':'attachment; filename="PagerWatch-config-backup.json"'});return
            if path=='/api/archive':
                if not self.archive:raise ValueError('Session library not ready')
                query=parse_qs(urlsplit(h.path).query)
                listing=self.archive.listing(int(query.get('offset',['0'])[0]))
                with self.lock:current=self.state
                for row in listing['sessions']:
                    row['active']=row['id']==current.get('session')
                    if row['active']:
                        row['devices']=len(current.get('devices',[]));row['observations']=current.get('processed',0)
                self.response(h,200,listing);return
            if path=='/api/archive/compare':
                if not self.archive:raise ValueError('Session library not ready')
                query=parse_qs(urlsplit(h.path).query)
                before=query.get('before',[''])[0];after=query.get('after',[''])[0]
                if before==after:raise ValueError('Choose two different runs')
                self.archive.directory(before);self.archive.directory(after)
                with self.lock:current=self.state
                old=current if before==current.get('session') else self.archive.review(before)
                new=current if after==current.get('session') else self.archive.review(after)
                self.response(h,200,compare_sessions(old,new));return
            if path=='/api/archive/session':
                if not self.archive:raise ValueError('Session library not ready')
                query=parse_qs(urlsplit(h.path).query);ident=query.get('id',[''])[0]
                self.archive.directory(ident)
                with self.lock:current=self.state
                if ident==current.get('session'):
                    review=dict(current,session_label=small_json(self.archive.directory(ident)/'session-info.json',4096).get('label',''),files=['observations.jsonl','discoveries.jsonl'],active=True)
                else:review=self.archive.review(ident)
                self.response(h,200,review);return
            if path=='/download/archive':
                if not self.archive:raise ValueError('Session library not ready')
                query=parse_qs(urlsplit(h.path).query);ident=query.get('session',[''])[0];name=query.get('file',[''])[0]
                self.archive.directory(ident)
                if name=='session-report.html':
                    with self.lock:current=self.state
                    review=current if ident==current.get('session') else self.archive.review(ident)
                    self.response(h,200,render_report(review),'text/html; charset=utf-8',{'Content-Disposition':'attachment; filename="session-report.html"'});return
                file=self.archive.file(ident,name);size=file.stat().st_size
                with self.lock:
                    if ident==self.state.get('session'):
                        if name=='observations.jsonl':size=min(size,self.log_bytes)
                        if name=='discoveries.jsonl':size=min(size,self.discovery_bytes)
                h.send_response(200);h.send_header('Content-Type','text/csv; charset=utf-8' if name.endswith('.csv') else 'application/json' if name.endswith('.json') else 'application/vnd.tcpdump.pcap' if name.endswith('.pcap') else 'application/x-ndjson')
                h.send_header('Content-Length',str(size));h.send_header('Cache-Control','no-store');h.send_header('X-Content-Type-Options','nosniff');h.send_header('Content-Disposition','attachment; filename="'+name+'"');h.end_headers()
                with file.open('rb') as stream:
                    while size:
                        chunk=stream.read(min(size,65536))
                        if not chunk:break
                        h.wfile.write(chunk);size-=len(chunk)
                return
            if path=='/api/discoveries':
                query=parse_qs(urlsplit(h.path).query)
                with self.lock:
                    file=self.discovery_path;size=self.discovery_bytes;session=self.state.get('session','')
                if query.get('session',[''])[0]!=session:
                    self.response(h,409,{'error':'Session changed; refresh the records'});return
                cursor=int(query.get('cursor',['0'])[0])
                if cursor<0 or cursor>size:raise ValueError('Invalid discovery cursor')
                points=[];end=cursor
                if file:
                    with file.open('rb') as stream:
                        if cursor:
                            stream.seek(cursor-1)
                            if stream.read(1)!=b'\n':raise ValueError('Cursor must be a record boundary')
                        stream.seek(cursor)
                        while len(points)<500 and end<size and end-cursor<262144:
                            line=stream.readline(min(65536,size-end))
                            if not line.endswith(b'\n'):raise ValueError('Incomplete discovery record')
                            points.append(json.loads(line));end+=len(line)
                self.response(h,200,{'session':session,'points':points,'cursor':end,'more':end<size});return
            if path=='/api/state':
                query=parse_qs(urlsplit(h.path).query)
                self.last_request=time.monotonic()
                with self.lock:state=dict(self.state)
                view=query.get('view',['full'])[0]
                chosen=query.get('selected',[''])[0]
                if view!='full':
                    # List/radar views do not need three GPS fixes, evidence byte tables
                    # and per-device history on every poll. Selected details remain full.
                    fields=('key','protocol','address','name','network_name','local_label','bookmarked','known','rssi_average','rssi_samples','rssi_average_age',
                            'rssi','last_rssi','rssi_age','age','frame','wifi_role','ssid_status','hits','vendor')
                    state['devices']=[dict({k:d.get(k) for k in fields},history=[],uuids=[],manufacturer={},bluetooth={}) if d['key']!=chosen else d for d in state.get('devices',[])]
                    state['points']=[]
                state['gps']=self.phone.status(owner,include_trail=view=='full');state['gps']['health']=gps_health(state['gps']);state['bridge']=self.bridge.status
                self.response(h,200,state);return
            if path.startswith('/download/'):
                name=path[len('/download/'):]
                with self.lock:state=self.state;log_path=self.log_path;log_bytes=self.log_bytes;report=self.report_path
                if name=='session-report.html':
                    self.response(h,200,render_report(state),'text/html; charset=utf-8',{'Content-Disposition':'attachment; filename="session-report.html"'});return
                if name=='devices.csv':
                    out=io.StringIO();writer=csv.writer(out);writer.writerow(['protocol','address','name','RSSI','seen','classification','rank','first_lat','first_lon','last_lat','last_lon','last_accuracy_m','last_observed_unix','strongest_lat','strongest_lon','strongest_rssi_dbm','local_label','bookmarked','known','rssi_average','rssi_samples','rssi_average_age','advertised_security','pmf','known'])
                    def safe(value):
                        value=str(value if value is not None else '')
                        return "'"+value if value.lstrip().startswith(('=','+','-','@')) else value
                    for d in state.get('devices',[]):
                        hit=d['hits'][0] if d['hits'] else {}
                        writer.writerow([safe(v) for v in [d['protocol'],d['address'],d.get('network_name') or d['name'],d['rssi'],d['seen'],hit.get('label',''),hit.get('score',''),
                            (d.get('first_location') or {}).get('lat'),(d.get('first_location') or {}).get('lon'),
                            (d.get('last_location') or {}).get('lat'),(d.get('last_location') or {}).get('lon'),
                            (d.get('last_location') or {}).get('accuracy_m'),(d.get('last_location') or {}).get('observed_at'),
                            (d.get('strongest_location') or {}).get('lat'),(d.get('strongest_location') or {}).get('lon'),
                            (d.get('strongest_location') or {}).get('rssi'),d.get('local_label',''),d.get('bookmarked',False),(d.get('security') or {}).get('label',''),(d.get('security') or {}).get('pmf',''),d.get('known',False)]])
                    body=out.getvalue().encode();kind='text/csv; charset=utf-8'
                elif name=='discoveries.jsonl':
                    with self.lock:file=self.discovery_path;size=self.discovery_bytes
                    if not file:self.response(h,404,{'error':'No session yet'});return
                    h.send_response(200);h.send_header('Content-Type','application/vnd.tcpdump.pcap' if name.endswith('.pcap') else 'application/x-ndjson')
                    h.send_header('Content-Length',str(size));h.send_header('Content-Disposition','attachment; filename="discoveries.jsonl"')
                    h.send_header('Cache-Control','no-store');h.send_header('X-Content-Type-Options','nosniff');h.end_headers()
                    with file.open('rb') as stream:
                        while size:
                            chunk=stream.read(min(size,65536))
                            if not chunk:break
                            h.wfile.write(chunk);size-=len(chunk)
                    return
                elif name=='wardrive.csv' and log_path:
                    # Stream the persistent JSONL log; CSV does not depend on map retention.
                    h.send_response(200);h.send_header('Content-Type','text/csv; charset=utf-8')
                    h.send_header('Content-Disposition','attachment; filename="wardrive.csv"')
                    h.send_header('Cache-Control','no-store');h.send_header('X-Content-Type-Options','nosniff');h.end_headers()
                    columns=['protocol','address','name','observed_unix','frequency_mhz','rssi_dbm','latitude','longitude','accuracy_m','location_source','advertised_name']
                    out=io.StringIO();writer=csv.writer(out);writer.writerow(columns)
                    h.wfile.write(out.getvalue().encode());out.seek(0);out.truncate(0)
                    with log_path.open('rb') as stream:
                        remaining=log_bytes
                        while remaining>0:
                            line=stream.readline(min(remaining,65536));remaining-=len(line)
                            if not line:break
                            try:record=json.loads(line)
                            except ValueError:continue
                            gps=record.get('observer_location');obs=record.get('observation',{})
                            if not gps:continue
                            values=[obs.get('protocol'),obs.get('address'),record.get('network_name') or obs.get('name'),obs.get('timestamp'),obs.get('frequency'),obs.get('rssi'),gps.get('lat'),gps.get('lon'),gps.get('accuracy_m'),gps.get('source','gpsd'),obs.get('name')]
                            values=[("'"+v if isinstance(v,str) and v.lstrip().startswith(('=','+','-','@')) else v) for v in values]
                            writer.writerow(values);h.wfile.write(out.getvalue().encode());out.seek(0);out.truncate(0)
                    return
                elif name=='observer.geojson':
                    features=[{'type':'Feature','geometry':{'type':'Point','coordinates':[p['lon'],p['lat']]},
                               'properties':{k:v for k,v in p.items() if k not in ('lat','lon')}} for p in state.get('points',[])]
                    body=json.dumps({'type':'FeatureCollection','features':features}).encode();kind='application/geo+json'
                elif name=='observations.jsonl' and log_path:
                    h.send_response(200)
                    h.send_header('Content-Type','application/vnd.tcpdump.pcap' if name.endswith('.pcap') else 'application/x-ndjson')
                    h.send_header('Content-Length',str(log_bytes))
                    h.send_header('Content-Disposition','attachment; filename="observations.jsonl"')
                    h.send_header('Cache-Control','no-store')
                    h.send_header('X-Content-Type-Options','nosniff')
                    h.end_headers()
                    with log_path.open('rb') as stream:
                        remaining=log_bytes
                        while remaining:
                            chunk=stream.read(min(65536,remaining))
                            if not chunk:break
                            h.wfile.write(chunk);remaining-=len(chunk)
                    return
                elif name=='diagnostic-report.zip' and report and report.is_file():body=report.read_bytes();kind='application/zip'
                else:self.response(h,404,{'error':'Export not available yet'});return
                self.response(h,200,body,kind,{'Content-Disposition':'attachment; filename="'+name+'"'});return
            self.response(h,404,{'error':'Unknown endpoint'})
        except NotebookConflict as exc:self.response(h,409,{'error':str(exc)})
        except NotebookConflict as exc:self.response(h,409,{'error':str(exc)})
        except (ValueError,TypeError,KeyError) as exc:self.response(h,400,{'error':str(exc)})
        except OSError:self.response(h,503,{'error':'File or connection unavailable'})

    def add_observation(self,obs,gps,accepted=True,device=None):
        if not gps or not accepted:return
        key=obs.protocol+':'+obs.address
        if obs.timestamp-self.point_times.get(key,0)<5:return
        self.point_times[key]=obs.timestamp;self.point_times.move_to_end(key)
        while len(self.point_times)>10000:self.point_times.popitem(last=False)
        self.points.append({'lat':gps['lat'],'lon':gps['lon'],'accuracy_m':gps.get('accuracy_m'),
                            'time':obs.timestamp,'segment':gps.get('segment'),'key':key,'protocol':obs.protocol,'name':obs.name,
                            'rssi':obs.rssi,'address':obs.address,'frequency':obs.frequency,
                            'matched':bool(device and device.hits),'label':device.hits[0].label if device and device.hits else '',
                            'network_name':device.ap_name if device else '', 'location_source':gps.get('source','gpsd'),'position_kind':'observer'})

    def result(self,command,ok,message):
        self.results.append({'id':command['id'],'ok':ok,'message':message,'action':command.get('action')})

    def wants_snapshot(self):
        return time.monotonic()-self.last_request<10

    def publish(self,session,workers,dropped=0):
        began=time.monotonic()
        self.detector=session.detector
        self.archive=SessionArchive(session.path.parent)
        now=time.time();devices=[]
        for key,d in reversed(list(session.devices.items())):
            o=d.obs;devices.append({'key':key,'protocol':o.protocol,'address':o.address,'name':o.name,
                'rssi':o.rssi,'frequency':o.frequency,'wifi_role':'ap' if d.ap_seen else 'client' if o.frame=='probe_request' else 'unidentified',
                'ssid_status':d.ssid_status or o.ssid_status,
                'last_rssi':d.history[-1][1] if d.history else None,
                'rssi_age':max(0,round(now-d.history[-1][0],1)) if d.history else None,'age':max(0,round(now-o.timestamp,1)),
                'first_seen':d.first_seen,'last_seen':o.timestamp,'seen':d.seen,'frame':o.frame,
                'address_type':o.address_type,'uuids':o.uuids,'manufacturer':o.manufacturer,'service_data':o.service_data,'metadata_source':o.metadata_source,
                'local_label':self.config.get('device_notes',{}).get(key,{}).get('label',''),
                'bookmarked':self.config.get('device_notes',{}).get(key,{}).get('bookmark',False),
                'known':self.config.get('device_notes',{}).get(key,{}).get('known',False),**d.signal_average(now),
                'security':d.security,'security_time':d.security_time,
                'hits':[asdict(hit) for hit in d.hits],'vendor':d.vendor,'bluetooth':d.bluetooth,
                'history':list(d.history),'ssids':list(d.ssid_names),'network_name':d.ap_name,
                'first_location':d.first_location,'last_location':d.last_location,'strongest_location':d.strongest_location})
        coverage=getattr(workers.get('Wi-Fi'),'coverage',None)
        state={'coverage':coverage.snapshot() if coverage else {},'version':'1.0.8','session':session.path.name,'now':now,'started':session.started,
               'session_label':small_json(session.path/'session-info.json',4096).get('label',''),
               'profile':self.config.get('scan_profile','survey'),'privacy':self.config.get('privacy_mode',False),
               'field_summary':session.field_summary(),'restore_pending':self.restore_pending,
               'reliability':session.reliability,'preflight':session.preflight,'checkpoint':{'time':session.checkpoint_at,'error':session.checkpoint_error},
               'known_keys':[k for k,v in self.config.get('device_notes',{}).items() if v.get('known')],
               'known_devices':[dict(v,key=k) for k,v in self.config.get('device_notes',{}).items() if v.get('known')],
               'tracked_key':session.tracked_key,'watch_rules':list(self.config.get('watch_rules',[])),
               'storage':session.storage_health.snapshot(session),
               'devices':devices,'alerts':list(session.alerts),'processed':session.events,'observation_bytes':session.bytes_written,
               'dropped':dropped,'evicted':session.evicted,'log_error':session.log_error,
               'scanners':{key:{'status':w.status,'metrics':dict(getattr(w,'metrics',{})),
                               'channels':[]} for key,w in workers.items()},
               'config':{key:self.config.get(key) for key in ('wifi_scan_mode','wifi_interface','ble_backend')},
               'wifi_adapters':getattr(workers.get('Wi-Fi'),'adapter_snapshot',lambda:{})(),
               'results':list(self.results),'points':list(self.points),
               'discovery_count':len(session.discovery_keys),'discovery_error':session.discovery_error,
               'geotagged_observations':session.located_events,'geotagged_devices':sum(d.last_location is not None for d in session.devices.values()),
               'report_ready':(session.path/'diagnostic-report.zip').is_file()}
        state['snapshot_ms']=round((time.monotonic()-began)*1000,2)
        with self.lock:
            self.discovery_path=session.path/'discoveries.jsonl';self.discovery_bytes=session.discovery_bytes
            self.state=state;self.log_path=session.path/'observations.jsonl';self.log_bytes=session.bytes_written
            self.report_path=session.path/'diagnostic-report.zip'
