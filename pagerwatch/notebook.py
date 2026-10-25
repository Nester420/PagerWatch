# SPDX-License-Identifier: GPL-3.0-or-later
"""Private, bounded research annotations. No extra Python packages or remote fetches."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import struct
import threading
import time
from urllib.parse import urlsplit
from .fieldtools import validate_note,clean_text
from .recovery import atomic_json

MAX_PHOTO=2*1024*1024
MAX_STORE=64*1024*1024
PHOTO_ID=re.compile(r'^[a-f0-9]{32}$')


def radio_key(key):return validate_note({'key':key})['key']


def reference_url(value):
    if not isinstance(value,str) or len(value)>1000 or any(ord(c)<=32 or ord(c)==127 for c in value):raise ValueError('Use a public HTTP(S) reference URL without spaces')
    try:
        parsed=urlsplit(value)
        if parsed.scheme not in ('https','http') or not parsed.hostname or parsed.username or parsed.password:raise ValueError()
        parsed.port
    except ValueError:raise ValueError('Use an HTTP(S) reference URL without embedded credentials')
    return value


def photo_type(data):
    if not 24<=len(data)<=MAX_PHOTO:raise ValueError('Photo must be at most 2 MB')
    width=height=None
    if data.startswith(b'\x89PNG\r\n\x1a\n') and data[12:16]==b'IHDR' and data[-8:]==b'IEND\xaeB`\x82':
        width,height=struct.unpack('>II',data[16:24]);mime,ext='image/png','png'
    elif data[:2]==b'\xff\xd8' and data[-2:]==b'\xff\xd9':
        mime,ext='image/jpeg','jpg';offset=2
        while offset+4<=len(data):
            if data[offset]!=255:break
            while offset<len(data) and data[offset]==255:offset+=1
            if offset>=len(data):break
            marker=data[offset];offset+=1
            if marker==0xDA:break
            if marker in (0x01,0xD8) or 0xD0<=marker<=0xD7:continue
            length=int.from_bytes(data[offset:offset+2],'big')
            if length<2 or offset+length>len(data):break
            if marker in (0xC0,0xC1,0xC2,0xC3,0xC5,0xC6,0xC7,0xC9,0xCA,0xCB,0xCD,0xCE,0xCF) and length>=8:
                height,width=struct.unpack('>HH',data[offset+3:offset+7]);break
            offset+=length
    else:raise ValueError('Upload a JPEG or PNG photo; other file types are not accepted')
    if not width or not height or width>4096 or height>4096 or width*height>16000000:raise ValueError('Photo dimensions are invalid or too large')
    return mime,ext


class NotebookConflict(ValueError):pass


class ResearchStore:
    def __init__(self,root):self.root=Path(root);self.lock=threading.RLock()
    def _directories(self,create=False):
        if self.root.parent.is_symlink() or self.root.is_symlink():raise ValueError('Invalid notebook directory')
        for folder in (self.root,self.root/'notes',self.root/'photos'):
            if folder.is_symlink():raise ValueError('Invalid notebook directory')
            if create:folder.mkdir(parents=True,exist_ok=True,mode=0o700)
        return self.root/'notes',self.root/'photos'
    def _path(self,key):
        key=radio_key(key);notes,_=self._directories()
        return notes/(hashlib.sha256(key.encode()).hexdigest()+'.json')
    def _get(self,key):
        key=radio_key(key);path=self._path(key)
        if path.is_symlink():raise ValueError('Invalid notebook entry')
        if not path.exists():return dict(key=key,revision=0,notes='',links=[],photos=[],updated=None)
        with path.open('rb') as stream:raw=stream.read(65537)
        if len(raw)>65536:raise ValueError('Notebook entry is too large')
        value=json.loads(raw)
        if not isinstance(value,dict) or value.get('key')!=key or type(value.get('revision')) is not int or not isinstance(value.get('photos'),list) or len(value['photos'])>6:raise ValueError('Invalid notebook entry')
        if not isinstance(value.get('notes'),str) or len(value['notes'])>8000 or not isinstance(value.get('links'),list) or len(value['links'])>8:raise ValueError('Invalid notebook entry')
        for link in value['links']:reference_url(link)
        return value
    def get(self,key):
        with self.lock:return self._get(key)
    def _check(self,current,revision):
        if type(revision) is not int or revision!=current['revision']:raise NotebookConflict('Notebook changed. Reload it before saving again.')
    def _usage(self):
        total=count=entries=0
        for folder in self._directories():
            if not folder.exists():continue
            with os.scandir(folder) as stream:
                for row in stream:
                    if not row.is_file(follow_symlinks=False):raise ValueError('Unexpected notebook file')
                    entries+=1
                    if entries>16000:raise ValueError('Notebook file limit reached')
                    total+=row.stat(follow_symlinks=False).st_size
                    if folder.name=='notes':count+=1
                    if count>2000 or total>MAX_STORE:raise ValueError('Notebook storage limit reached; export and remove old attachments')
        return total,count
    def _write(self,current,extra=0):
        self._directories(True);total,count=self._usage()
        path=self._path(current['key']);new=dict(current,revision=current['revision']+1,updated=time.time())
        raw=json.dumps(new,ensure_ascii=True).encode()
        if len(raw)>65536:raise ValueError('Notebook entry is too large')
        if (not path.exists() and count>=2000) or total+len(raw)+extra>MAX_STORE:raise ValueError('Notebook storage limit reached (64 MB / 2000 addresses)')
        if shutil.disk_usage(self.root).free<len(raw)+1048576:raise ValueError('Not enough free space for the research notebook')
        atomic_json(path,new);return new
    def save(self,key,notes,links,revision):
        if not isinstance(notes,str) or len(notes)>8000 or any(ord(c)<32 and c not in '\n\t\r' for c in notes):raise ValueError('Notes must be plain text up to 8000 characters')
        if not isinstance(links,list) or len(links)>8:raise ValueError('Save up to eight reference links')
        links=list(dict.fromkeys(reference_url(v) for v in links))
        with self.lock:
            current=self._get(key);self._check(current,revision);current.update(notes=notes,links=links)
            return self._write(current)
    def add_photo(self,key,encoded,name,revision):
        if not isinstance(encoded,str) or len(encoded)>(MAX_PHOTO+2)//3*4:raise ValueError('Photo must be at most 2 MB')
        try:data=base64.b64decode(encoded,validate=True)
        except (ValueError,TypeError):raise ValueError('Invalid photo encoding')
        mime,ext=photo_type(data);name=clean_text(name,80) or 'Research photo'
        with self.lock:
            current=self._get(key);self._check(current,revision)
            if len(current['photos'])>=6:raise ValueError('Save up to six photos per address')
            self._directories(True);ident=secrets.token_hex(16);path=self.root/'photos'/(ident+'.'+ext)
            photo=dict(id=ident,name=name,mime=mime,ext=ext,bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),added=time.time())
            total,_=self._usage()
            if total+len(data)+65536>MAX_STORE:raise ValueError('Notebook storage limit reached (64 MB)')
            if shutil.disk_usage(self.root).free<len(data)+65536+1048576:raise ValueError('Not enough free space for this research photo')
            created=False
            try:
                with path.open('xb') as stream:
                    created=True;os.chmod(path,0o600);stream.write(data);stream.flush();os.fsync(stream.fileno())
                current['photos'].append(photo);return self._write(current)
            except Exception:
                if created:path.unlink(missing_ok=True)
                raise
    def _photo(self,key,ident):
        if not isinstance(ident,str) or not PHOTO_ID.fullmatch(ident):raise ValueError('Invalid photo ID')
        current=self._get(key);photo=next((p for p in current['photos'] if p.get('id')==ident),None)
        if not photo or photo.get('ext') not in ('jpg','png'):raise ValueError('Photo not found')
        path=self.root/'photos'/(ident+'.'+photo['ext'])
        if path.is_symlink():raise ValueError('Invalid photo path')
        with path.open('rb') as stream:data=stream.read(MAX_PHOTO+1)
        if len(data)>MAX_PHOTO or hashlib.sha256(data).hexdigest()!=photo.get('sha256'):raise ValueError('Photo file failed integrity check')
        actual_mime,actual_ext=photo_type(data)
        if actual_mime!=photo.get('mime') or actual_ext!=photo.get('ext'):raise ValueError('Photo type metadata is invalid')
        return photo,data
    def photo(self,key,ident):
        with self.lock:return self._photo(key,ident)
    def remove_photo(self,key,ident,revision):
        with self.lock:
            current=self._get(key);self._check(current,revision)
            if not isinstance(ident,str) or not PHOTO_ID.fullmatch(ident):raise ValueError('Invalid photo ID')
            photo=next((p for p in current['photos'] if p.get('id')==ident),None)
            if not photo or photo.get('ext') not in ('jpg','png'):raise ValueError('Photo not found')
            current['photos']=[p for p in current['photos'] if p['id']!=ident];new=self._write(current)
            (self.root/'photos'/(ident+'.'+photo['ext'])).unlink(missing_ok=True);return new
    def status(self):
        with self.lock:
            total,count=self._usage();path=self.root
            while not path.exists():path=path.parent
            return dict(bytes=total,limit_bytes=MAX_STORE,addresses=count,free_bytes=shutil.disk_usage(path).free)
    def export(self,key):
        with self.lock:
            current=self._get(key);photos=[self._photo(key,p['id']) for p in current['photos']]
            return current,photos
