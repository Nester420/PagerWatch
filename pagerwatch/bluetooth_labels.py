# SPDX-License-Identifier: GPL-3.0-or-later
"""Advertised Bluetooth registrants and category hints; never detection rules."""
import json
import re


def short_service(value):
    value = str(value).lower()
    if re.fullmatch(r'(?:0x)?[0-9a-f]{4}', value):
        return value.removeprefix('0x').upper()
    match = re.fullmatch(r'0000([0-9a-f]{4})-0000-1000-8000-00805f9b34fb', value)
    return match.group(1).upper() if match else None


def company_number(value):
    try:
        if isinstance(value, bool):
            return None
        text = str(value)
        if not re.fullmatch(r'(?:[0-9]+|0[xX][0-9a-fA-F]+)', text):
            return None
        number = int(text, 16 if text.lower().startswith('0x') else 10)
        return number if 0 <= number <= 65535 else None
    except (ValueError, TypeError):
        return None


class BluetoothLabels:
    def __init__(self, path):
        with open(path, encoding='utf-8') as stream:
            self.data = json.load(stream)
        for name in ('full', 'makerCat', 'serviceCat', 'serviceMaker'):
            table = self.data.get(name)
            if not isinstance(table, dict):
                raise ValueError('Invalid Bluetooth table: ' + name)
            for key, value in table.items():
                if not isinstance(key, str):
                    raise ValueError('Invalid Bluetooth key')
                if name in ('full', 'serviceMaker'):
                    valid = isinstance(value, str)
                else:
                    valid = isinstance(value, list) and len(value) == 2 and all(isinstance(x, str) for x in value)
                if not valid:
                    raise ValueError('Invalid Bluetooth entry: ' + name)
        self.company_count = len(self.data['full'])
        self.service_count = len(self.data['serviceMaker'])

    def lookup(self, obs):
        if obs.protocol != 'ble':
            return {}
        companies, services, categories = [], [], []
        numbers = {company_number(key) for key in obs.manufacturer}
        for number in sorted(n for n in numbers if n is not None):
            key = '%04X' % number
            companies.append({'id': key, 'name': self.data['full'].get(str(number), 'Unknown company')})
            category = self.data['makerCat'].get(key)
            if category:
                categories.append({'category': category[0], 'source': 'company:' + key})
        keys = {short_service(key) for key in list(obs.uuids) + list(obs.service_data)}
        for key in sorted(k for k in keys if k is not None):
            owner = self.data['serviceMaker'].get(key)
            category = self.data['serviceCat'].get(key)
            # Keep only catalogued services; the raw observation retains all UUIDs.
            if owner or category:
                services.append({'uuid': key, 'owner': owner or 'Unknown service owner'})
            if category:
                categories.append({'category': category[0], 'source': 'service:' + key})
        return {'companies': companies, 'services': services, 'category_hints': categories}


def label_lines(context):
    lines = ['BLE company 0x%s: %s' % (item['id'], item['name']) for item in context.get('companies', [])]
    lines += ['Service %s owner: %s' % (item['uuid'], item['owner']) for item in context.get('services', [])]
    lines += ['Category hint: %s (%s)' % (item['category'], item['source']) for item in context.get('category_hints', [])]
    return lines


def fallback_name(context):
    names = list(dict.fromkeys(item['name'] for item in context.get('companies', []) if item['name'] != 'Unknown company'))
    if not names:
        names = list(dict.fromkeys(item['owner'] for item in context.get('services', []) if item['owner'] != 'Unknown service owner'))
    return names[0] if len(names) == 1 else 'Multiple BLE registrants' if names else ''
