# SPDX-License-Identifier: GPL-3.0-or-later
"""Exact-address comparisons and confirmation-bound, flat-folder session removal."""
import os
import secrets
import stat
import threading
import time
from .archive import SESSION_ID
from .fieldtools import KEY


def compare_sessions(before,after):
    def inventory(run):
        result={}
        for row in run.get('devices',[])[:2000]:
            protocol=row.get('protocol');address=str(row.get('address','')).upper()
            key=str(protocol)+':'+address
            if not KEY.fullmatch(key):continue
            result[key]={k:row.get(k) for k in ('name','network_name','local_label','rssi','last_rssi','hits','known')}
            result[key].update(key=key,protocol=protocol,address=address)
        return result
    old,new=inventory(before),inventory(after)
    groups={'new':[new[k] for k in sorted(new.keys()-old.keys())],
            'returning':[new[k] for k in sorted(new.keys()&old.keys())],
            'not_seen':[old[k] for k in sorted(old.keys()-new.keys())]}
    partial=any(len(run.get('devices',[]))>2000 or run.get('truncated') or run.get('evicted') or (run.get('recovery') or {}).get('limited') for run in (before,after))
    return {'before':before.get('session'),'after':after.get('session'),'groups':groups,
            'counts':{key:len(value) for key,value in groups.items()},'partial':bool(partial),
            'note':'Exact protocol/address inventory comparison. Not seen means absent from the compared inventory; it does not prove a device has left. Rotated addresses remain separate.'}


def _manifest(fd):
    """Reject links, nested folders and special files; never follow a session entry."""
    rows=[]
    with os.scandir(fd) as entries:
        for entry in entries:
            info=entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):raise ValueError('Session contains a link, folder or special file; manage it with WinSCP')
            rows.append([entry.name,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns])
            if len(rows)>512:raise ValueError('Session has too many files; manage it with WinSCP')
    return sorted(rows)


def _open(archive,ident,active):
    if ident==active:raise ValueError('The active run cannot be deleted')
    if not isinstance(ident,str) or not SESSION_ID.fullmatch(ident):raise ValueError('Invalid session ID')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW
    root=os.open(archive.root,flags)
    try:folder=os.open(ident,flags,dir_fd=root)
    except Exception:os.close(root);raise
    return root,folder


def deletion_preview(archive,ids,active):
    if not isinstance(ids,list) or not 1<=len(ids)<=25 or any(not isinstance(i,str) for i in ids) or len(set(ids))!=len(ids):
        raise ValueError('Select 1–25 distinct saved runs')
    manifests=[]
    for ident in ids:
        root,folder=_open(archive,ident,active)
        try:
            info=os.fstat(folder);files=_manifest(folder)
            manifests.append({'id':ident,'inode':info.st_ino,'device':info.st_dev,'files':files})
        finally:os.close(folder);os.close(root)
    return manifests


def delete_sessions(archive,manifests,active):
    """Own-thread action. Validate the whole batch again before unlinking selected files."""
    if not isinstance(manifests,list) or not 1<=len(manifests)<=25:raise ValueError('Invalid deletion request')
    opened=[];removed=0;size=0
    try:
        for run in manifests:
            root,folder=_open(archive,run['id'],active);opened.append((root,folder,run))
            info=os.fstat(folder)
            if info.st_ino!=run['inode'] or info.st_dev!=run['device'] or _manifest(folder)!=run['files']:
                raise ValueError('Selected run changed. Review the deletion again.')
        for root,folder,run in opened:
            info=os.stat(run['id'],dir_fd=root,follow_symlinks=False)
            if info.st_ino!=run['inode'] or info.st_dev!=run['device'] or not stat.S_ISDIR(info.st_mode):raise ValueError('Selected folder changed')
            for name,_,length,_,_ in run['files']:
                os.unlink(name,dir_fd=folder);size+=length
            os.rmdir(run['id'],dir_fd=root);removed+=1
        return removed,size
    except OSError as exc:
        raise ValueError('Deletion stopped after %d runs; refresh the list. %s'%(removed,str(exc)[:100])) from exc
    finally:
        for root,folder,_ in opened:os.close(folder);os.close(root)


class DeletionTickets:
    """Short-lived, one-use tickets bound to the authenticated browser session."""
    def __init__(self):self.lock=threading.Lock();self.tickets={}
    def prepare(self,owner,manifests):
        with self.lock:
            now=time.monotonic();self.tickets={k:v for k,v in self.tickets.items() if v[1]>now}
            if len(self.tickets)>=16:self.tickets.pop(next(iter(self.tickets)))
            token=secrets.token_urlsafe(24);self.tickets[token]=(owner,now+180,manifests)
        return {'token':token,'count':len(manifests),'bytes':sum(f[2] for m in manifests for f in m['files']),'expires_seconds':180}
    def queue(self,owner,token,commands):
        if not isinstance(token,str):raise ValueError('Review selected runs before deleting')
        with self.lock:
            value=self.tickets.get(token)
            if not value or value[0]!=owner or value[1]<time.monotonic():raise ValueError('Deletion confirmation expired. Review selected runs again.')
            ident=secrets.token_hex(6)
            commands.put_nowait({'id':ident,'action':'session_delete','value':value[2]})
            del self.tickets[token]
            return ident
