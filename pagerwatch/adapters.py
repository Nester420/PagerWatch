# SPDX-License-Identifier: GPL-3.0-or-later
"""Read-only Linux interface metadata for choosing one Wi-Fi capture radio."""
from pathlib import Path
import re


def valid_interface(name):
    return isinstance(name,str) and re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',name) is not None


def interface_metadata(name,sysroot='/sys/class/net'):
    if not valid_interface(name):raise ValueError('Invalid Wi-Fi interface name')
    device=Path(sysroot)/name/'device'
    try:
        resolved=device.resolve(strict=True)
        usb=any((parent/'subsystem').resolve().name=='usb' for parent in [resolved,*resolved.parents])
    except OSError:usb=False
    try:driver=(device/'driver').resolve(strict=True).name
    except OSError:driver='unknown'
    return {'usb':usb,'driver':driver}


def adapter_rows(available):
    rows=[]
    for item in available[:32]:
        if valid_interface(item.get('name')):
            rows.append({key:item.get(key) for key in ('name','type','phy','frequency')} | interface_metadata(item['name']))
    return rows


def adaptive_candidates(available, sysroot='/sys/class/net'):
    """Pager convention plus physical identity: onboard wlan0/wlan1 are USB too.

    Never classify another interface on an onboard PHY/device as external.
    Unknown non-USB devices are not automatically borrowed.
    """
    internal_phys=set();internal_paths=set()
    for item in available:
        if re.fullmatch(r'wlan[01](?:mon|cli|ap)?',item['name']):
            if item.get('phy'):internal_phys.add(item['phy'])
    for name in ('wlan0','wlan1','wlan0mon','wlan1mon','wlan0cli'):
        try:internal_paths.add((Path(sysroot)/name/'device').resolve(strict=True))
        except OSError:pass
    choices=[]
    for item in available:
        if item.get('type') not in ('monitor','managed') or item['name'].startswith('pwmon'):continue
        metadata=interface_metadata(item['name'],sysroot)
        try:path=(Path(sysroot)/item['name']/'device').resolve(strict=True)
        except OSError:path=None
        onboard=item.get('phy') in internal_phys or (path is not None and path in internal_paths)
        external=metadata['usb'] and not onboard
        if onboard or external:
            choices.append(dict(item,external=external))
    return sorted(choices,key=lambda i:(not i['external'],i['type']!='monitor',i['name']!='wlan1mon',i['name']))

class AdapterRetries:
    """Short, bounded retries for devices that appear before firmware is ready."""
    def __init__(self):self.entries={}
    def reconcile(self,present):
        self.entries={k:v for k,v in self.entries.items() if k in present}
    def fail(self,key,now):
        attempts=self.entries.get(key,{}).get('attempts',0)+1
        self.entries[key]={'attempts':attempts,'next':now+min(15,2**min(attempts,4))}
    def ready(self,key,now):return now>=self.entries.get(key,{}).get('next',0)
    def due(self,now):return any(self.ready(k,now) for k in self.entries)
    def snapshot(self,now):return [{'interface':k[0],'phy':k[1],'attempts':v['attempts'],'retry_in':round(max(0,v['next']-now),1)} for k,v in self.entries.items()]
