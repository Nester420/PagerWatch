from .detection_check import check_target, device_row
import textwrap
# SPDX-License-Identifier: GPL-3.0-or-later
"""Button-driven field tools; archive reads run off the capture/UI thread."""
from dataclasses import asdict
import math
import queue
import threading
import time
from .archive import SessionArchive
from .fieldtools import apply_note,apply_rule,gps_health
from .sessiontools import compare_sessions,deletion_preview,delete_sessions
from .research import research_document,device_record
import textwrap
from .research import research_document,device_record,utc_stamp
import textwrap

GREEN=0xB7F522
FG=0xD9EACB
MUTED=0x829E75
AMBER=0xFFC15A
PANEL=0x0B1C0C


def duration(value):
    if not isinstance(value,(int,float)):return 'Unavailable'
    value=max(0,int(value));return '%dh %02dm %02ds'%(value//3600,value//60%60,value%60)


def size(value):return '%.2f MB'%(value/1048576)


class NativeTools:
    def __init__(self,screen):
        self.s=screen;self.active=False;self.view='';self.index=0
        self.generation=0;self.job=None;self.results=queue.Queue(maxsize=1)
        self.archive=SessionArchive(screen.session.path.parent)
        self.rows=[];self.offset=0;self.next_offset=None;self.run=None;self.review=None
        self.research=None;self.research_offset=0;self.research_pages=[];self.research=None;self.research_offset=0;self.research_pages=[];self.comparison=None;self.category=0;self.target=None;self.preview=None;self.preview_until=0

    @property
    def private(self):return bool(self.s.session.config.get('privacy_mode',False))

    def field_labels(self):
        config=self.s.session.config
        return ['Survey','Track (choose target)','Quiet','Privacy: '+('ON' if self.private else 'OFF'),
                'Run summary','Phone GPS','Known gear','Hide known: '+('ON' if self.s.hide_known else 'OFF'),'Saved runs']

    def field_input(self,pressed):
        p=self.s.p;count=len(self.field_labels())
        if pressed & p.BTN_UP:self.s.field_index=(self.s.field_index-1)%count
        elif pressed & p.BTN_DOWN:self.s.field_index=(self.s.field_index+1)%count
        elif pressed & p.BTN_A:
            index=self.s.field_index
            if index<3:self.s.profile_requested=('survey','track','quiet')[index]
            elif index==3:self.s.privacy_requested=not self.private
            elif index==4:self.open('summary')
            elif index==5:self.open('gps')
            elif index==6:self.open('known');self.refresh_known()
            elif index==7:
                self.s.hide_known=not self.s.hide_known;self.s.index=0;self.s.radar_selected=None
                self.s.notice('Known gear hidden on Pager' if self.s.hide_known else 'Known gear visible on Pager')
            else:self.open('sessions');self.load_sessions(0)
        elif pressed & (p.BTN_B|p.BTN_POWER):self.s.confirm='EXIT'

    def open(self,view):
        self.generation+=1;self.active=True;self.view=view;self.index=0;self.preview=None

    def close(self):
        self.generation+=1;self.active=False;self.preview=None;self.review=None;self.comparison=None

    def submit(self,kind,function):
        if self.job is not None:self.s.notice('Archive busy; please wait');return False
        generation=self.generation;self.job=kind
        def read():
            try:result=(True,function())
            except Exception as exc:result=(False,str(exc)[:180])
            self.results.put((generation,kind,result))
        threading.Thread(target=read,daemon=True,name='pagerwatch-native-read').start()
        return True

    def pump(self):
        try:generation,kind,(ok,value)=self.results.get_nowait()
        except queue.Empty:return
        self.job=None
        if generation!=self.generation or not self.active:return
        if not ok:self.s.notice(value);return
        if kind=='sessions':
            self.rows=value['sessions'];self.offset=value['offset'];self.next_offset=value['next'];self.index=0
            for row in self.rows:
                if row['id']==self.s.session.path.name:
                    row['devices']=len(self.s.session.devices);row['observations']=self.s.session.events
        elif kind=='review':self.review=value;self.view='review';self.index=0
        elif kind=='compare':self.comparison=value;self.view='compare';self.category=0;self.index=0
        elif kind=='research':self.research=value;self.view='research';self.index=0;self.research_offset=value['history']['offset']
        elif kind=='research':self.research=value;self.view='research';self.index=0;self.research_offset=value['history']['offset']
        elif kind=='delete':
            self.preview=value;self.preview_until=time.monotonic()+180;self.view='delete';self.index=0

    def load_sessions(self,offset):
        self.submit('sessions',lambda:self.archive.listing(offset))

    def refresh_known(self):
        self.rows=[dict(note,key=key) for key,note in sorted(self.s.session.config.get('device_notes',{}).items()) if note.get('known')]
        self.index=min(self.index,max(0,len(self.rows)-1))

    def open_device(self,key):
        if self.private:self.s.notice('Turn Privacy off to edit an address');return
        self.target=key;self.open('device')

    def note(self,key):return dict(self.s.session.config.get('device_notes',{}).get(key,{}))

    def save_note(self,key,**updates):
        value=self.note(key);value.update(updates,key=key)
        apply_note(self.s.session.config,value)
        try:self.s.on_save()
        except OSError:self.s.notice('Applied this run; settings save failed')
        else:self.s.notice('Device details saved')

    def active_inventory(self):
        # Capture a bounded immutable snapshot on the owning thread before a read job.
        session=self.s.session;rows=[]
        for key,device in list(session.devices.items())[-2000:]:
            obs=device.obs;note=self.note(key)
            rows.append(dict(key=key,protocol=obs.protocol,address=obs.address,name=obs.name,network_name=device.ap_name,
                             local_label=note.get('label',''),known=note.get('known',False),rssi=obs.rssi,
                             hits=[asdict(hit) for hit in device.hits]))
        return dict(session=session.path.name,devices=rows,evicted=session.evicted,truncated=len(session.devices)>2000)

    def device_labels(self):
        note=self.note(self.target)
        rule=next((r for r in self.s.session.config.get('watch_rules',[]) if r.get('kind')=='address' and r.get('target')==self.target),None)
        return ['Bookmark: '+('ON' if note.get('bookmark') else 'OFF'),'Known gear: '+('YES' if note.get('known') else 'NO'),
                'Address watch: '+('ON' if rule and rule.get('enabled',True) else 'OFF'),'Track this signal','Exclude future sightings...','Research / past sightings','Why detected / not alerted?']

    def input(self,pressed):
        p=self.s.p
        if pressed & p.BTN_POWER:self.close();self.s.confirm='EXIT';return
        if pressed & p.BTN_B:
            if self.job is not None:self.generation+=1
            if self.view in ('summary','gps','known','sessions','device'):self.close()
            elif self.view in ('run','compare','review','delete'):self.view='sessions';self.preview=None;self.index=0
            elif self.view=='detection':self.view='device';self.index=0
            elif self.view=='research':self.view='device' if self.s.detail else 'inventory';self.index=0
            elif self.view=='research':self.view='device' if self.s.detail else 'inventory';self.index=0
            elif self.view=='inventory':self.view='review';self.index=0
            elif self.view=='unmark':self.view='known'
            return
        if not pressed:return
        if self.view=='detection':
            if pressed & p.BTN_UP:self.index=max(0,self.index-1)
            elif pressed & p.BTN_DOWN:self.index=min(max(0,len(self.check_lines)-6),self.index+1)
            return
        if self.view in ('summary','gps'):return
        if self.view=='delete':
            if pressed & p.BTN_A and self.preview:
                if time.monotonic()>self.preview_until:self.preview=None;self.s.notice('Confirmation expired; review run again');return
                preview=self.preview;self.preview=None
                try:
                    count,freed=delete_sessions(self.archive,preview,self.s.session.path.name)
                    self.s.notice('Deleted %d run / %s'%(count,size(freed)))
                    self.view='sessions';self.run=None;self.review=None;self.comparison=None;self.rows=[];self.load_sessions(self.offset)
                except (OSError,ValueError) as exc:
                    self.view='run';self.s.notice(str(exc))
            return
        if self.view=='device':
            if self.job:return
            if self.private:self.s.notice('Turn Privacy off to edit an address');return
            if pressed & p.BTN_UP:self.index=(self.index-1)%len(self.device_labels())
            elif pressed & p.BTN_DOWN:self.index=(self.index+1)%len(self.device_labels())
            elif pressed & p.BTN_A:
                try:
                    if self.index==0:self.save_note(self.target,bookmark=not self.note(self.target).get('bookmark',False))
                    elif self.index==1:self.save_note(self.target,known=not self.note(self.target).get('known',False))
                    elif self.index==2:
                        rule=next((r for r in self.s.session.config.get('watch_rules',[]) if r.get('kind')=='address' and r.get('target')==self.target),None)
                        value=dict(rule,enabled=not rule.get('enabled',True)) if rule else dict(kind='address',target=self.target,label=self.note(self.target).get('label') or 'Pager address watch',enabled=True)
                        apply_rule(self.s.session.config,value)
                        try:self.s.on_save()
                        except OSError:self.s.notice('Watch applied this run; save failed')
                        else:self.s.notice('Address watch updated')
                    elif self.index==3:
                        if self.target not in self.s.session.devices:raise ValueError('Target no longer retained')
                        self.s.hunt_key=self.target;self.s.hunt_sound=False;self.close()
                    elif self.index==6:
                        session=self.s.session;device=session.devices.get(self.target)
                        if not device:raise ValueError('Target no longer retained')
                        protocol,address=self.target.split(':',1)
                        result=check_target({'rules_version':session.detector.version,'devices':[device_row(self.target,device,session)]},
                            {'excluded':list(session.excluded),'threshold':session.config.get('alert_threshold',75),'profile':session.config.get('scan_profile')},protocol,address,self.s.hide_known)
                        lines=[result['decision'].replace('_',' '),'Rules '+str(result['rules_version'])+' / threshold '+str(result['alert_threshold'])]+result['notes']
                        lines += [h['label']+' / score '+str(h['score']) for h in result['matches']]
                        self.check_lines=[part for line in lines for part in textwrap.wrap(line,68)]
                        self.view='detection';self.index=0
                    elif self.index==5:
                        self.research_pages=[];self.load_research(0)
                    elif self.index==5:
                        self.research_pages=[];self.load_research(0)
                    else:
                        if not self.s.detail or self.s.contact_key(self.s.detail)!=self.target:raise ValueError('Open this device again before excluding')
                        self.close();self.s.confirm='EXCLUDE'
                except ValueError as exc:self.s.notice(str(exc))
            return
        if self.view=='known':
            if pressed & p.BTN_UP:self.index=max(0,self.index-1)
            elif pressed & p.BTN_DOWN:self.index=min(max(0,len(self.rows)-1),self.index+1)
            elif pressed & p.BTN_A and self.rows:
                if self.private:self.s.notice('Turn Privacy off to edit an address');return
                self.target=self.rows[self.index]['key'];self.view='unmark'
            return
        if self.view=='unmark':
            if pressed & p.BTN_A:
                if self.private:self.s.notice('Turn Privacy off to edit an address');return
                try:self.save_note(self.target,known=False);self.view='known';self.refresh_known()
                except ValueError as exc:self.s.notice(str(exc))
            return
        if self.view=='sessions':
            if self.job:return
            if pressed & p.BTN_UP:self.index=max(0,self.index-1)
            elif pressed & p.BTN_DOWN:self.index=min(max(0,len(self.rows)-1),self.index+1)
            elif pressed & p.BTN_RIGHT and self.next_offset is not None:self.load_sessions(self.next_offset)
            elif pressed & p.BTN_LEFT and self.offset:self.load_sessions(max(0,self.offset-25))
            elif pressed & p.BTN_A and self.rows:self.run=dict(self.rows[self.index]);self.view='run';self.index=0
            return
        if self.view=='run':
            if self.job:return
            if pressed & p.BTN_UP:self.index=(self.index-1)%3
            elif pressed & p.BTN_DOWN:self.index=(self.index+1)%3
            elif pressed & p.BTN_A and self.run:
                ident=self.run['id'];active=self.s.session.path.name
                if self.index==0:
                    if ident==active:self.view='summary'
                    else:self.submit('review',lambda:self.archive.review(ident))
                elif self.index==1:
                    if ident==active:self.s.notice('Select a saved run as the baseline');return
                    current=self.active_inventory()
                    self.submit('compare',lambda:compare_sessions(self.archive.review(ident),current))
                else:
                    if ident==active:self.s.notice('The active run cannot be deleted');return
                    self.submit('delete',lambda:deletion_preview(self.archive,[ident],active))
            return
        if self.view=='review':
            if pressed & p.BTN_A and self.review:self.view='inventory';self.index=0
            return
        if self.view=='research':
            if self.job:return
            if pressed & p.BTN_DOWN:self.index+=1
            elif pressed & p.BTN_UP:self.index=max(0,self.index-1)
            elif pressed & p.BTN_RIGHT and self.research and self.research['history']['next_offset'] is not None:
                self.research_pages.append(self.research_offset);self.load_research(self.research['history']['next_offset'])
            elif pressed & p.BTN_LEFT and self.research_pages:self.load_research(self.research_pages.pop())
            return
        if self.view=='research':
            if self.job:return
            if pressed & p.BTN_DOWN:self.index+=1
            elif pressed & p.BTN_UP:self.index=max(0,self.index-1)
            elif pressed & p.BTN_RIGHT and self.research and self.research['history']['next_offset'] is not None:
                self.research_pages.append(self.research_offset);self.load_research(self.research['history']['next_offset'])
            elif pressed & p.BTN_LEFT and self.research_pages:self.load_research(self.research_pages.pop())
            return
        if self.view=='inventory':
            rows=(self.review or {}).get('devices',[])
            if pressed & p.BTN_UP:self.index=max(0,self.index-1)
            elif pressed & p.BTN_DOWN:self.index=min(max(0,len(rows)-1),self.index+1)
            elif pressed & p.BTN_A and rows:
                if self.private:self.s.notice('Turn Privacy off to load address research');return
                self.target=rows[self.index]['key'];self.research_pages=[];self.load_research(0)
            return
        if self.view=='compare':
            if pressed & p.BTN_LEFT:self.category=(self.category-1)%3;self.index=0
            elif pressed & p.BTN_RIGHT:self.category=(self.category+1)%3;self.index=0
            rows=(self.comparison or {}).get('groups',{}).get(('new','returning','not_seen')[self.category],[])
            if pressed & p.BTN_UP:self.index=max(0,self.index-1)
            elif pressed & p.BTN_DOWN:self.index=min(max(0,len(rows)-1),self.index+1)

    def load_research(self,offset):
        store=getattr(self.s.session,'research_store',None)
        if store is None:self.s.notice('Research notebook unavailable; relaunch PagerWatch');return
        current=self.active_inventory();device=self.s.session.devices.get(self.target)
        if device:
            current['devices']=[device_record(device,self.s.session.config.get('device_notes',{}))]
        key=self.target
        self.submit('research',lambda:research_document(self.archive,store,key,current,self.s.session.detector,offset))

    def research_lines(self):
        if not self.research:return ['No research loaded.']
        doc=self.research;card=doc['identification'];n=doc['notebook'];h=doc['history']
        lines=[card['summary']]
        for match in card.get('matches',[]):lines+=['RULE: '+match['label']+' / rank '+str(match.get('rank')),match.get('evidence','')]
        lines+=card.get('cautions',[])
        lines+=['USER NOTES (not radio evidence):',n['notes'] or 'No saved notes.',
                'Photos: %d (view/export in dashboard)'%len(n['photos'])]
        for link in list(dict.fromkeys(card.get('references',[])+n.get('links',[]))):lines+=['REFERENCE (manual): '+link]
        lines+=['PAST SIGHTINGS / %d runs checked'%h['scanned_runs'],h['note']]
        if h['limited']:lines+=['PARTIAL READ: older/limited logs may omit sightings.']
        for row in h['matches']:
            lines+=[row['session_label'] or row['session'],'First %s / latest %s'%(utc_stamp(row.get('first_seen')),utc_stamp(row.get('last_seen'))),
                    '%s %s'%(row.get('observations'),row.get('count_kind'))]
            fix=row.get('last_location')
            if fix:lines+=['Receiver location: %.6f, %.6f'%(fix['lat'],fix['lon'])]
        if not h['matches']:lines+=['No matches on this history page.']
        return [part for line in lines for part in (textwrap.wrap(str(line),74) or [''])]

    def load_research(self,offset):
        store=getattr(self.s.session,'research_store',None)
        if store is None:self.s.notice('Research notebook unavailable; relaunch PagerWatch');return
        current=self.active_inventory();device=self.s.session.devices.get(self.target)
        if device:
            current['devices']=[device_record(device,self.s.session.config.get('device_notes',{}))]
        key=self.target
        self.submit('research',lambda:research_document(self.archive,store,key,current,self.s.session.detector,offset))

    def research_lines(self):
        if not self.research:return ['No research loaded.']
        doc=self.research;card=doc['identification'];n=doc['notebook'];h=doc['history']
        lines=[card['summary']]
        for match in card.get('matches',[]):lines+=['RULE: '+match['label']+' / rank '+str(match.get('rank')),match.get('evidence','')]
        lines+=card.get('cautions',[])
        lines+=['USER NOTES (not radio evidence):',n['notes'] or 'No saved notes.',
                'Photos: %d (view/export in dashboard)'%len(n['photos'])]
        for link in list(dict.fromkeys(card.get('references',[])+n.get('links',[]))):lines+=['REFERENCE (manual): '+link]
        lines+=['PAST SIGHTINGS / %d runs checked'%h['scanned_runs'],h['note']]
        if h['limited']:lines+=['PARTIAL READ: older/limited logs may omit sightings.']
        for row in h['matches']:
            lines+=[row['session_label'] or row['session'],'First %s / latest %s'%(row.get('first_seen'),row.get('last_seen')),
                    '%s %s'%(row.get('observations'),row.get('count_kind'))]
            fix=row.get('last_location')
            if fix:lines+=['Receiver location: %.6f, %.6f'%(fix['lat'],fix['lon'])]
        if not h['matches']:lines+=['No matches on this history page.']
        return [part for line in lines for part in (textwrap.wrap(str(line),74) or [''])]

    def footer(self):
        if self.view=='detection':return 'UP/DN scroll  B device actions'
        if self.view=='device':return 'UP/DN select  A apply  B details'
        if self.view=='sessions':return 'UP/DN select  A open  LEFT/RIGHT pages  B back'
        if self.view=='run':return 'UP/DN select  A open  B saved runs'
        if self.view=='compare':return 'LEFT/RIGHT category  UP/DN scroll  B back'
        if self.view=='known':return 'UP/DN select  A unmark known  B field'
        if self.view in ('delete','unmark'):return 'A confirm  B cancel'
        if self.view=='review':return 'A inventory  B saved runs'
        if self.view=='inventory':return 'UP/DN scroll  A research  B summary'
        if self.view=='research':return 'UP/DN scroll  LEFT/RIGHT history pages  B back'
        return 'B back to FIELD'

    def title(self,text,detail=''):
        self.s.text(10,54,text,GREEN,2)
        if detail:self.s.text(10,77,detail,MUTED)

    def label(self,row):
        if self.private:return 'Private contact'
        return row.get('local_label') or row.get('label') or row.get('network_name') or row.get('name') or '?'

    def address(self,key):return '[hidden address]' if self.private else key

    def list_rows(self,rows,session_rows=False):
        self.index=min(self.index,max(0,len(rows)-1));start=(self.index//4)*4
        for index,row in enumerate(rows[start:start+4],start):
            y=92+(index-start)*24
            if index==self.index:self.s.box(5,y-2,470,24,PANEL)
            if session_rows:
                ident=row['id'];active=ident==self.s.session.path.name
                label='Private session' if self.private else row.get('label') or ident
                detail=('ACTIVE / ' if active else 'Saved / ' if row.get('closed') else 'Unfinished / ')+size(row['bytes'])+' / '+str(row.get('devices') or 0)+' addresses'
            else:
                label=self.label(row);key=row.get('key') or str(row.get('protocol',''))+':'+str(row.get('address',''))
                detail=self.address(key)
            self.s.text(10,y,('> ' if index==self.index else '  ')+label[:69],GREEN if index==self.index else FG)
            self.s.text(22,y+11,detail,MUTED)
        if not rows:self.s.text(12,111,'No entries in this view.',MUTED)
        self.s.text(10,190,('%d/%d'%(self.index+1,len(rows))) if rows else '0 entries',MUTED)

    def draw_field(self):
        s=self.s;labels=self.field_labels();start=(s.field_index//5)*5
        self.title('FIELD CONTROLS')
        for index,label in enumerate(labels[start:start+5],start):
            active=index<3 and s.session.config.get('scan_profile','survey')==('survey','track','quiet')[index]
            s.text(10,83+(index-start)*18,('> ' if index==s.field_index else '  ')+label+(' *' if active else ''),GREEN if index==s.field_index else FG)
        s.text(10,184,'%d/%d / UP/DN for more'%(s.field_index+1,len(labels)),MUTED)
        summary=s.session.field_summary();storage=s.session.storage
        s.text(290,81,'RUN '+duration(summary['duration_seconds']),GREEN)
        s.text(290,101,'Wi-Fi %d / BLE %d'%(summary['retained_wifi'],summary['retained_ble']),FG)
        percent=summary['gps_coverage_percent'];s.text(290,121,'GPS: '+('%.1f%%'%percent if percent is not None else 'no sightings'),FG)
        s.text(290,141,'Free: '+size(storage['free_bytes']) if 'free_bytes' in storage else 'Storage unavailable',MUTED)
        s.text(290,161,'Records: '+('WARNING' if storage.get('warnings') or s.session.checkpoint_error else 'local'),AMBER if storage.get('warnings') or s.session.checkpoint_error else MUTED)

    def draw_summary(self,field,title='RUN SUMMARY'):
        self.title(title,duration(field.get('duration_seconds')))
        s=self.s;pct=field.get('gps_coverage_percent');reasons=field.get('gps_reasons')
        s.text(10,95,'WI-FI %s / BLE %s'%(field.get('retained_wifi','?'),field.get('retained_ble','?')),FG,2)
        s.text(10,119,'GPS '+('%.1f%%'%pct if pct is not None else '--')+' / %s of %s sightings'%(field.get('geotagged_observations','?'),field.get('observations','?')),GREEN)
        if isinstance(reasons,dict):
            s.text(10,139,'Misses: stale %d / low accuracy %d'%(reasons.get('stale',0),reasons.get('inaccurate',0)),FG)
            s.text(10,156,'Unavailable / no aligned fix: %d'%reasons.get('unavailable',0),FG)
        else:s.text(10,143,'GPS miss reasons unavailable for this older run.',MUTED)
        s.text(10,190,'Address counts / display filters do not change logs.',MUTED)

    def draw_gps(self):
        s=self.s;gps=dict(s.session.gps_status);web=s.workers.get('Web')
        if web:gps=web.phone.status()
        self.title('PHONE GPS',gps_health(gps).split(' — ')[0])
        s.text(10,95,'Accuracy: %s m / age: %s s'%(gps.get('accuracy_m') if gps.get('accuracy_m') is not None else '--',gps.get('age_seconds') if gps.get('age_seconds') is not None else '--'),FG)
        coords=all(isinstance(gps.get(k),(int,float)) and math.isfinite(gps[k]) for k in ('lat','lon'))
        s.text(10,114,'Latitude:  '+('[hidden]' if self.private else '%.6f'%gps['lat'] if coords else '--'),FG,2)
        s.text(10,132,'Longitude: '+('[hidden]' if self.private else '%.6f'%gps['lon'] if coords else '--'),FG,2)
        speed=gps.get('speed_mps');heading=gps.get('heading_deg');valid=gps.get('valid',False)
        moving=isinstance(speed,(int,float)) and math.isfinite(speed) and speed>=0
        speed_text='[hidden]' if self.private else '%.1f MPH'%(speed*2.2369362920544) if valid and moving else '--'
        heading_text='[hidden]' if self.private else '%s %d deg'%((('N','NE','E','SE','S','SW','W','NW')[int(heading/45+.5)%8]),round(heading)%360) if valid and isinstance(heading,(int,float)) and math.isfinite(heading) and 0<=heading<360 and speed!=0 else '--'
        s.text(10,153,speed_text,GREEN,2)
        s.text(240,153,heading_text,GREEN,2)
        s.text(10,178,'Start phone sharing in dashboard; keep phone connected.',MUTED)
        s.text(10,190,'Satellite count is not provided by phone browsers.',MUTED)

    def draw(self,now):
        s=self.s
        if self.view=='detection':
            self.title('DETECTION CHECK',self.address(self.target))
            if self.private:s.text(10,111,'Detection details hidden by Privacy.',AMBER);return
            for i,line in enumerate(self.check_lines[self.index:self.index+6]):s.text(10,96+i*15,line,FG)
            return
        if self.view=='summary':self.draw_summary(s.session.field_summary());return
        if self.view=='gps':self.draw_gps();return
        if self.view=='known':
            self.title('KNOWN GEAR','Saved exact addresses / '+('HIDDEN on Pager' if s.hide_known else 'visible on Pager'));self.list_rows(self.rows);return
        if self.view=='unmark':
            self.title('UNMARK KNOWN GEAR?');s.text(10,99,self.address(self.target),FG)
            s.text(10,124,'Label and bookmark stay saved.',MUTED);return
        if self.view=='device':
            self.title('DEVICE ACTIONS',self.address(self.target))
            if self.private:s.text(10,113,'Turn Privacy off to identify and edit this address.',AMBER);return
            for i,label in enumerate(self.device_labels()):s.text(10,94+i*15,('> ' if i==self.index else '  ')+label,GREEN if i==self.index else FG)
            return
        if self.view=='research':
            self.title('DEVICE RESEARCH',self.address(self.target))
            if self.private:s.text(10,111,'Research hidden by Privacy. Use FIELD to turn it off.',AMBER);return
            lines=self.research_lines();self.index=min(self.index,max(0,len(lines)-6))
            for i,line in enumerate(lines[self.index:self.index+6]):s.text(10,96+i*15,line,FG)
            s.text(10,190,'%d-%d / %d lines'%(self.index+1,min(self.index+6,len(lines)),len(lines)),MUTED)
        elif self.view=='sessions':
            self.title('SAVED RUNS','Page %d / capture continues'%(self.offset//25+1));self.list_rows(self.rows,True)
        elif self.view=='run':
            self.title('SESSION ACTIONS','Private session' if self.private else (self.run or {}).get('label') or (self.run or {}).get('id',''))
            active=(self.run or {}).get('id')==s.session.path.name
            for i,label in enumerate(('Run summary / inventory','Compare baseline vs current','Delete run (active protected)' if active else 'Delete this saved run...')):s.text(10,101+i*25,('> ' if i==self.index else '  ')+label,GREEN if i==self.index else FG)
        elif self.view=='review':
            self.draw_summary((self.review or {}).get('field_summary',{}),'SAVED RUN SUMMARY')
            if (self.review or {}).get('recovery'):s.text(10,175,'Interrupted run / totals at last checkpoint',AMBER)
            elif (self.review or {}).get('truncated'):s.text(10,175,'Partial saved inventory; see exported logs',AMBER)
        elif self.view=='inventory':
            self.title('SAVED INVENTORY','Read-only snapshot / not live');self.list_rows((self.review or {}).get('devices',[]))
        elif self.view=='compare':
            data=self.comparison or {};counts=data.get('counts',{})
            title=('NEW ADDRESSES','RETURNING','NOT SEEN IN CURRENT')[self.category]
            self.title(title,'New %d / returning %d / not seen %d'%(counts.get('new',0),counts.get('returning',0),counts.get('not_seen',0)))
            self.list_rows(data.get('groups',{}).get(('new','returning','not_seen')[self.category],[]))
            s.text(95,190,'Partial inventory' if data.get('partial') else 'Inventory only / not proof of absence' if self.category==2 else 'Exact addresses / snapshot',AMBER if data.get('partial') else MUTED)
        elif self.view=='delete':
            self.title('DELETE SAVED RUN?','Private session' if self.private else (self.run or {}).get('label') or (self.run or {}).get('id',''))
            total=sum(row[2] for run in self.preview or [] for row in run['files'])
            s.text(10,102,size(total)+' / all files in this run',AMBER,2)
            s.text(10,132,'Logs, checkpoints and reports will be removed.',FG)
            s.text(10,151,'Permanent. Cannot undo. Active run is protected.',AMBER)
            s.text(10,175,'Confirmation expired; B to return' if time.monotonic()>self.preview_until else 'A deletes this run / B cancels',MUTED)
        if self.job:s.box(4,181,472,20,PANEL);s.text(10,187,'Loading archive... capture continues. B cancels.',GREEN)
