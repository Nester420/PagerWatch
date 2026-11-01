# SPDX-License-Identifier: GPL-3.0-or-later
"""Receive-side HCI advertising decoding and hcitool name compatibility."""
from collections import OrderedDict
import re
import socket
import ctypes
import os
import struct
import time
import uuid
from .detection import Observation, uuid128


def advertisement(address, address_type, data, rssi, now):
    obs = Observation('ble', address, rssi=rssi if rssi != 127 else None,
                      timestamp=now, address_type={0:'public', 1:'random', 2:'public', 3:'random'}.get(address_type,'unknown'),
                      metadata_source='hci_advertisement')
    pos = 0
    while pos < len(data):
        length = data[pos]
        if not length:
            break
        if pos + 1 + length > len(data):
            return None  # Never classify a truncated AD structure.
        kind = data[pos+1]
        value = data[pos+2:pos+length+1]
        pos += length+1
        if kind in (8,9):
            name = value.decode('utf-8','replace').replace('\x00','')
            if kind == 9 or not obs.name:
                obs.name = name
        elif kind in (2,3,4,5,6,7):
            width = 2 if kind in (2,3) else 4 if kind in (4,5) else 16
            if len(value) % width:
                continue
            for offset in range(0,len(value),width):
                part = value[offset:offset+width]
                service = str(uuid.UUID(bytes=part[::-1])) if width == 16 else '%08x-0000-1000-8000-00805f9b34fb' % int.from_bytes(part,'little')
                obs.uuids.append(service)
        elif kind == 255 and len(value) >= 2:
            obs.manufacturer[str(int.from_bytes(value[:2],'little'))] = value[2:].hex()
        elif kind in (22,32,33):
            width = {22:2,32:4,33:16}[kind]
            if len(value) < width:
                continue
            part = value[:width]
            service = str(uuid.UUID(bytes=part[::-1])) if width == 16 else '%08x-0000-1000-8000-00805f9b34fb' % int.from_bytes(part,'little')
            obs.service_data[service] = value[width:].hex()
    obs.advertising_data_hex = data.hex()
    obs.uuids = sorted(set(obs.uuids))
    return obs


def hci_event(packet, now=None):
    """H4 LE Meta events: legacy and complete extended advertising reports."""
    now = time.time() if now is None else now
    if len(packet) < 5 or packet[:2] != b'\x04\x3e' or len(packet) != packet[2]+3:
        return []
    subevent, count = packet[3:5]
    if subevent not in (2,13):
        return []
    pos, results = 5, []
    for _ in range(count):
        fixed = 9 if subevent == 2 else 24
        if pos+fixed > len(packet):
            return []
        if subevent == 2:
            kind, address_type = packet[pos:pos+2]
            address = packet[pos+2:pos+8]
            length = packet[pos+8]
            end = pos+9+length
            if end >= len(packet):
                return []
            rssi = int.from_bytes(packet[end:end+1],'little',signed=True)
            data = packet[pos+9:end]
            pos = end+1
        else:
            kind = int.from_bytes(packet[pos:pos+2],'little')
            address_type = packet[pos+2]
            address = packet[pos+3:pos+9]
            rssi = int.from_bytes(packet[pos+13:pos+14],'little',signed=True)
            length = packet[pos+23]
            end = pos+24+length
            if end > len(packet):
                return []
            data = packet[pos+24:end]
            pos = end
            if kind & 0x60:  # Incomplete fragments / truncated extended data.
                continue
        if address_type == 255:  # Anonymous report, no stable address to index.
            continue
        mac = ':'.join('%02X'%b for b in address[::-1])
        obs = advertisement(mac,address_type,data,rssi,now)
        if obs is not None:
            results.append(obs)
    return results if pos == len(packet) else []


class RawHciParser:
    """Bounded hcidump --raw multiline H4 packets; no shell execution."""
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, line, now=None):
        line = line.strip()
        if line.startswith(('>','<')):
            self.buffer.clear()
            line = line[1:].strip()
        if not re.fullmatch(r'(?:[0-9a-fA-F]{2}(?:\s+|$))+',line):
            return []
        self.buffer.extend(bytes.fromhex(line))
        if len(self.buffer)>260 or self.buffer and self.buffer[0] != 4:
            self.buffer.clear()
            return []
        if len(self.buffer)<3:
            return []
        expected = self.buffer[2]+3
        if len(self.buffer)<expected:
            return []
        packet = bytes(self.buffer)
        self.buffer.clear()
        return hci_event(packet,now)


class AdvertisementCache:
    """Merge name/scan responses by address, with independently expiring fields."""
    def __init__(self,limit=2048,ttl=120):
        self.entries = OrderedDict()
        self.limit,self.ttl = limit,ttl

    def merge(self, obs):
        now = obs.timestamp
        key = obs.address
        entry = self.entries.pop(key,None)
        if entry is None or now-entry['seen']>self.ttl:
            entry={'obs':Observation('ble',key),'times':{},'seen':now}
        old,times = entry['obs'],entry['times']
        for field in ('name','address_type','rssi'):
            value = getattr(obs,field)
            if value not in ('','unknown',None):
                setattr(old,field,value)
                times[(field,'')] = now
        for field in ('manufacturer','service_data'):
            for k,v in getattr(obs,field).items():
                getattr(old,field)[k]=v
                times[(field,k)]=now
        for service in obs.uuids:
            if service not in old.uuids:
                old.uuids.append(service)
            times[('uuids',service)]=now
        for (field,k),stamp in list(times.items()):
            if now-stamp>(5 if field == 'rssi' else self.ttl):
                if field == 'uuids':
                    old.uuids=[u for u in old.uuids if u!=k]
                elif field in ('manufacturer','service_data'):
                    getattr(old,field).pop(k,None)
                else:
                    setattr(old,field,{'name':'','address_type':'unknown','rssi':None}[field])
                del times[(field,k)]
        old.timestamp=entry['seen']=now
        # The merged object can include metadata from an earlier scan response.
        old.metadata_source='hci_scan_cache'
        self.entries[key]=entry
        while len(self.entries)>self.limit:
            self.entries.popitem(last=False)
        data=old.to_dict()
        data['rssi'] = obs.rssi  # A name-only event is not a new signal measurement.
        data['metadata_seen'] = {}
        for (field, key), stamp in times.items():
            label = 'uuid:'+uuid128(key) if field == 'uuids' else 'company:'+key if field == 'manufacturer' else 'service:'+uuid128(key) if field == 'service_data' else field
            data['metadata_seen'][label] = stamp
        return Observation(**data)


def hcitool_name(line, now=None):
    match = re.fullmatch(r'\s*([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+(.+?)\s*',line)
    if not match:
        return None
    mac,name = match.groups()
    if name.lower() in ('(unknown)','unknown','(null)'):
        name=''
    return Observation('ble',mac.upper(),name=name,timestamp=time.time() if now is None else now,
                       metadata_source='hcitool_scan')


def open_hci_events(interface):
    """Linux raw HCI socket, filtered to receive LE Meta events only.

    Does not send HCI commands or change adapter/scan state.
    """
    if not re.fullmatch(r'hci[0-9]+',interface):
        raise ValueError('Invalid HCI interface')
    stream = socket.socket(getattr(socket,"AF_BLUETOOTH",31),socket.SOCK_RAW,getattr(socket,"BTPROTO_HCI",1))
    try:
        if hasattr(socket,"AF_BLUETOOTH"):
            stream.bind((int(interface[3:]),))
        else:
            # Some embedded Python builds omit Bluetooth address conversion.
            # Linux sockaddr_hci: family, device index, HCI_CHANNEL_RAW (all u16).
            libc = ctypes.CDLL(None,use_errno=True)
            libc.bind.argtypes = [ctypes.c_int,ctypes.c_void_p,ctypes.c_uint]
            libc.bind.restype = ctypes.c_int
            address = ctypes.create_string_buffer(struct.pack("=HHH",31,int(interface[3:]),0))
            if libc.bind(stream.fileno(),address,6) != 0:
                code = ctypes.get_errno()
                raise OSError(code,os.strerror(code))
        stream.setsockopt(0,2,struct.pack('=IIIH2x',1 << 4,0,1 << 30,0))
        stream.setblocking(False)
        return stream
    except Exception:
        stream.close()
        raise
