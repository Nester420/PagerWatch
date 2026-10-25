# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded parsing of advertised RSN/WPA information; never a security verdict."""
import struct

CIPHERS={0:'Use group',1:'WEP-40',2:'TKIP',4:'CCMP-128',5:'WEP-104',6:'BIP-CMAC-128',8:'GCMP-128',9:'GCMP-256',10:'CCMP-256',11:'BIP-GMAC-128',12:'BIP-GMAC-256',13:'BIP-CMAC-256'}
AKMS={1:'802.1X',2:'PSK',3:'FT-802.1X',4:'FT-PSK',5:'802.1X-SHA256',6:'PSK-SHA256',8:'SAE',9:'FT-SAE',11:'Suite-B',12:'Suite-B-192',18:'OWE'}

def suite(raw,table,oui):
    return table.get(raw[3],'Unknown suite '+raw.hex()) if raw[:3]==oui else 'Unknown suite '+raw.hex()

def parse_element(data,rsn=True):
    oui=b'\x00\x0f\xac' if rsn else b'\x00\x50\xf2'
    if len(data)<2 or struct.unpack_from('<H',data)[0]!=1:raise ValueError('Unknown RSN/WPA version')
    pos=2
    def take(n):
        nonlocal pos
        if pos+n>len(data):raise ValueError('Truncated security element')
        value=data[pos:pos+n];pos+=n;return value
    group=suite(take(4),CIPHERS,oui)
    def selectors(table):
        count=int.from_bytes(take(2),'little')
        if not 1<=count<=32:raise ValueError('Invalid security suite count')
        return [suite(take(4),table,oui) for _ in range(count)]
    pairs=selectors(CIPHERS);akm=selectors(AKMS)
    pmf='Not advertised'
    if rsn and pos<len(data):
        caps=int.from_bytes(take(2),'little');capable=bool(caps&128);required=bool(caps&64)
        if required and not capable:raise ValueError('Inconsistent PMF capabilities')
        pmf='Required' if required else 'Capable' if capable else 'Not advertised'
        if pos<len(data):
            count=int.from_bytes(take(2),'little')
            if count>16:raise ValueError('Invalid PMKID count')
            take(count*16)
            if pos<len(data):take(4)
    elif not rsn and pos<len(data):take(2)
    if pos!=len(data):raise ValueError('Unexpected security element tail')
    return {'protocol':'RSN' if rsn else 'WPA','group':group,'pairwise':pairs,'akm':akm,'pmf':pmf}

def advertised_security(capabilities,elements,complete=True):
    results=[];errors=[]
    for tag,value in elements:
        if tag==48 or (tag==221 and value.startswith(b'\x00\x50\xf2\x01')):
            try:results.append(parse_element(value if tag==48 else value[4:],tag==48))
            except ValueError as exc:errors.append(str(exc))
    if errors or not complete:
        return {'label':'Unknown / incomplete security advertisement','pmf':'Unknown','complete':False,'errors':errors[:4] or ['Truncated information elements']}
    if not results:
        return {'label':'Privacy bit set — legacy/unknown' if capabilities&16 else 'Open (advertised)', 'protocols':[], 'akm':[], 'pairwise':[], 'pmf':'Not advertised','complete':True}
    akms=sorted({a for r in results for a in r['akm']});pairs=sorted({a for r in results for a in r['pairwise']})
    rsn=next((r for r in results if r['protocol']=='RSN'),None)
    sae=any(a in ('SAE','FT-SAE') for a in akms);psk=any('PSK' in a for a in akms)
    if rsn:
        label='WPA2/WPA3-Personal transition' if sae and psk else 'WPA3-Personal (SAE advertised)' if sae else 'Enhanced Open (OWE advertised)' if 'OWE' in akms else 'WPA3-Enterprise 192-bit (advertised)' if 'Suite-B-192' in akms else 'WPA2-Personal (PSK advertised)' if psk else 'WPA2-Enterprise (802.1X advertised)' if any('802.1X' in a for a in akms) else 'RSN — unknown authentication'
    else:label='WPA (advertised)'
    return {'label':label,'protocols':[r['protocol'] for r in results],'akm':akms,'pairwise':pairs,'group':sorted({r['group'] for r in results}),'pmf':rsn['pmf'] if rsn else 'Not advertised','complete':True}
