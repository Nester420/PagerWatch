# SPDX-License-Identifier: GPL-3.0-or-later
"""Explain existing receive evidence without scanning, changing rules or re-alerting."""
import time
from dataclasses import asdict
from .detection import normalize_mac


def device_row(key, device, session):
    o=device.obs
    return dict(o.to_dict(),key=key, hits=[asdict(h) for h in device.hits],
                current_rule_ids=list(device.current_rule_ids),
                signature_last_seen={r:stamp for r,(hit,stamp) in device.signature_history.items()},
                alerted=key in session.alerted_keys,
                known=session.config.get('device_notes',{}).get(key,{}).get('known',False),last_seen=o.timestamp)


def check_target(state, policy, protocol, address, hide_known=False):
    if protocol not in ('wifi','ble'):
        raise ValueError('Choose Wi-Fi or Bluetooth')
    if not isinstance(address,str) or len(address)>64 or not normalize_mac(address):
        raise ValueError('Enter a complete MAC address, such as AA:BB:CC:DD:EE:FF')
    address=normalize_mac(address);key=protocol+':'+address
    excluded={str(x).upper() for x in policy.get('excluded',[])}
    ignored=address in excluded or key.upper() in excluded
    row=next((d for d in state.get('devices',[]) if d.get('key')==key),None)
    threshold=policy.get('threshold',75)
    hits=row.get('hits',[]) if row else []
    current=set(row.get('current_rule_ids',[])) if row else set()
    now=time.time()
    report={'time':now,'key':key,'rules_version':state.get('rules_version','unknown'),
            'alert_threshold':threshold,'received':bool(row),'excluded':ignored,
            'last_seen':row.get('last_seen') if row else None,
            'metadata':{'source':row.get('metadata_source',''), 'uuid_count':len(row.get('uuids',[])),
                        'company_count':len(row.get('manufacturer',{})), 'service_data_count':len(row.get('service_data',{})),
                        'address_type':row.get('address_type','unknown'), 'frame':row.get('frame',''),
                        'probe_ssid_status':row.get('probe_ssid_status','')} if row else {},
            'matches':[dict(h, current=h['rule'] in current,last_seen=row.get('signature_last_seen',{}).get(h['rule'])) for h in hits],
            'known_hidden':bool(hide_known and row and row.get('known')),
            'quiet':policy.get('profile')=='quiet', 'notes':[]}
    notes=report['notes']
    if ignored:
        decision='excluded';notes.append('This address is excluded from recording and alerting. Earlier records may still exist.')
    elif not row:
        decision='not_in_inventory';notes.append('No retained record for this protocol/address. It may not have been received, may have been evicted, or may advertise under another address. This does not prove the device is absent.')
    elif row.get('alerted'):
        decision='already_alerted';notes.append('An alert was already recorded for this exact protocol/address this session. Repeated alerts are intentionally suppressed.')
    elif not hits:
        decision='no_rule_match';notes.append('Received, but the available evidence did not match a detection rule. A manufacturer lookup alone does not confirm a product.')
    elif max(h['score'] for h in hits)<threshold:
        decision='below_threshold';notes.append('A signature matched, but its score is below your saved alert threshold.')
    elif not any(h['rule'] in current and h['score']>=threshold for h in hits):
        decision='earlier_evidence';notes.append('Earlier signature evidence is retained. The latest observation does not contain an eligible current match; it does not create a new alert.')
    else:
        decision='eligible';notes.append('Current evidence meets the threshold. No recorded alert appears in this snapshot; refresh or export diagnostics if this persists.')
    if row and now-row.get('last_seen',now)>30:
        notes.append('This is retained evidence from more than 30 seconds ago, not proof of current reception.')
    if report['known_hidden']:notes.append('Hide known devices hides this address and its alert rows in this browser. Recording still continues.')
    if report['quiet']:notes.append('Quiet profile suppresses sound/vibration; recorded matches remain available.')
    if row and protocol=='ble' and not any(report['metadata'].get(k) for k in ('uuid_count','company_count','service_data_count')):
        notes.append('No service or manufacturer fields are available for this address. Name/address reception alone may not identify a tracker.')
    notes.append('Check the exact protocol/address against your comparison detector. Randomized addresses are separate contacts.')
    report['decision']=decision
    report['receiver']=state.get('scanners',{}).get('BLE' if protocol=='ble' else 'Wi-Fi',{})
    return report
