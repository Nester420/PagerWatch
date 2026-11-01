# SPDX-License-Identifier: GPL-3.0-or-later
"""480x222 native Pager interface using an independently installed pagerctl."""
import hashlib
import copy
import math
import statistics
import textwrap
import time
from .responsive import Feedback
from .bluetooth_labels import fallback_name, label_lines
from .scanners import SCAN_MODES, MODE_NAMES, scan_mode
from .fieldtools import gps_health

BG = 0x020703
PANEL = 0x0B1C0C
FG = 0xD9EACB
MUTED = 0x829E75
CYAN = 0xB7F522
AMBER = 0xFFC15A
RED = 0xFF816D


def safe(text, count=75):
    # Radio names are untrusted text; remove terminal/control characters.
    return "".join(c if 32 <= ord(c) <= 126 else "?" for c in str(text))[:count]


class Screen:
    tabs = ["ALERTS", "WI-FI", "BLUETOOTH", "SIGNAL", "STATUS", "WEB", "COVER", "FIELD"]

    def __init__(self, pager, session, workers, on_save):
        self.p = pager
        self.feedback=Feedback(pager)
        self.session = session
        self.workers = workers
        self.on_save = on_save
        self.splash_active = False
        self.tab = 0
        self.coverage_offset = 0
        self.index = 0
        self.detail = None
        self.offset = 0
        self.confirm = None
        self.last_notice = ""
        self.notice_until = 0
        self.exit_requested = False
        self.scan_menu = False
        self.mode_index = 0
        self.mode_requested = None
        self.adapter_requested = None
        self.adapter_menu = False
        self.adapter_index = 0
        self.adapter_refresh_requested = False
        self.ble_menu = False
        self.ble_index = 0
        self.ble_backend_requested = None
        self.hunt_key = None
        self.hunt_sound = False
        self.hunt_feedback = 0
        self.radar_selected = None
        self.radar_filter = None
        self.radar_snapshot = None
        self.radar_menu = False
        self.radar_menu_index = 0
        self.diagnostic_view = False
        self.export_requested = False
        self.export_busy = False
        self.field_index = 0
        self.profile_requested = None
        self.privacy_requested = None
        self.hide_known = False
        from .native_tools import NativeTools
        self.tools = NativeTools(self)

    def start_splash(self, image_path):
        """Hold until A; ingestion continues without redrawing/decoding the image."""
        self.splash_active = True
        self.p.clear(self.p.hex_color(0x000000))
        try:
            result = self.p.draw_image_file_scaled(21, 0, 438, 202, str(image_path))
        except (AttributeError, OSError):
            result = -1
        if result != 0:
            self.text(120, 72, "PAGERWATCH", CYAN, 4)
            self.text(186, 120, "by Nester", CYAN, 2)
        self.text(198, 212, "A TO CONTINUE", MUTED)
        self.p.flip()

    def text(self, x, y, value, color=FG, scale=1):
        width = max(1, (480 - x) // (6 * scale))
        self.p.draw_text(x, y, safe(value, width), self.p.hex_color(color), scale)

    def box(self, x, y, width, height, color):
        self.p.fill_rect(x, y, width, height, self.p.hex_color(color))

    def notice(self, value):
        self.last_notice = value
        self.notice_until = time.time() + 4

    def notify(self, device):
        self.notice('Signature alert' if self.session.config.get('privacy_mode',False) else device.hits[0].label)
        if self.session.config.get("vibrate", True) and self.session.config.get('scan_profile')!='quiet':
            try:
                self.feedback.pulse()
            except (AttributeError, OSError):
                pass

    def selected(self):
        devices = self.list_devices()
        if not devices:
            return None
        self.index = min(self.index, len(devices) - 1)
        return devices[self.index]

    def is_known(self, device):
        return bool(self.session.config.get("device_notes",{}).get(self.contact_key(device),{}).get("known",False))

    def list_devices(self):
        protocol = "wifi" if self.tab == 1 else "ble" if self.tab == 2 else None
        devices = self.session.visible(matched=self.tab == 0, protocol=protocol)
        if self.hide_known:devices=[d for d in devices if not self.is_known(d)]
        if self.tab != 1:
            return devices
        groups = {}
        for device in devices:
            obs = device.obs
            key = ("ssid", getattr(device,"ap_name","") or obs.name) if self.is_named_ap(device) else ("address", obs.address)
            previous = groups.get(key)
            # Keep one representative row per SSID; raw BSSIDs remain separate.
            if previous is None or (bool(device.hits), obs.rssi if obs.rssi is not None else -999) > (bool(previous.hits), previous.obs.rssi if previous.obs.rssi is not None else -999):
                groups[key] = device
        return list(groups.values())

    @staticmethod
    def is_named_ap(device):
        return device.obs.protocol == "wifi" and bool(getattr(device,"ap_name","") or (device.obs.name if device.obs.frame in ("beacon", "probe_response", "scan_result") else ""))

    def network_members(self, device):
        if not self.is_named_ap(device):
            return [device]
        return [d for d in self.session.devices.values()
                if (not self.hide_known or not self.is_known(d)) and self.is_named_ap(d) and (getattr(d,"ap_name","") or d.obs.name) == (getattr(device,"ap_name","") or device.obs.name)]

    def wifi_adapter_choices(self):
        worker=self.workers.get('Wi-Fi')
        state=getattr(worker,'adapter_snapshot',lambda:{})()
        rows=[]
        for row in state.get('interfaces',[]):
            if row.get('type') in ('monitor','managed') and not row.get('owned'):
                rows.append((row['name'],row['name']+' / '+('USB / ' if row.get('usb') else '')+row['type']))
        return rows+[('__refresh__','Refresh adapters')]

    def radar_label(self, device):
        if device.obs.protocol=='wifi':
            return device.obs.name or (device.hits[0].label if device.hits else '?')
        return device.obs.name or fallback_name(device.bluetooth) or device.vendor.get('name') or device.obs.address

    def input(self, pressed):
        p = self.p
        self.tools.pump()
        if not pressed:return
        if self.splash_active:
            if pressed & p.BTN_A:
                self.splash_active = False
            elif pressed & p.BTN_POWER:
                self.exit_requested = True
            return
        if self.tools.active:
            self.tools.input(pressed)
            return
        if self.diagnostic_view:
            if pressed & p.BTN_B:
                self.diagnostic_view = False
            elif pressed & p.BTN_A and not self.export_busy:
                self.export_requested = True
            return
        if self.radar_menu:
            if pressed & p.BTN_B:
                self.radar_menu = False
            elif pressed & p.BTN_UP:
                self.radar_menu_index = (self.radar_menu_index-1)%4
            elif pressed & p.BTN_DOWN:
                self.radar_menu_index = (self.radar_menu_index+1)%4
            elif pressed & p.BTN_A:
                rows = self.radar_contacts(time.time())
                selected = next((d for d in rows if self.contact_key(d)==self.radar_selected),None)
                if self.radar_menu_index == 0 and selected:
                    self.detail = self.session.devices.get(self.radar_selected,selected)
                    self.offset = 0
                elif self.radar_menu_index == 1 and selected:
                    self.hunt_key = self.radar_selected
                    self.hunt_sound = False
                elif self.radar_menu_index == 2:
                    self.radar_filter = {None:"wifi","wifi":"ble","ble":None}[self.radar_filter]
                    self.radar_selected = None
                elif self.radar_menu_index == 3:
                    self.radar_snapshot = copy.deepcopy(list(self.session.devices.values())) if self.radar_snapshot is None else None
                self.radar_menu = False
            return
        if self.hunt_key:
            if pressed & p.BTN_B:
                self.hunt_key = None
            elif pressed & p.BTN_A:
                self.hunt_sound = not self.hunt_sound
            return
        if self.ble_menu:
            if pressed & p.BTN_B:
                self.ble_menu = False
            elif pressed & p.BTN_UP:
                self.ble_index = (self.ble_index-1)%3
            elif pressed & p.BTN_DOWN:
                self.ble_index = (self.ble_index+1)%3
            elif pressed & p.BTN_A:
                self.ble_backend_requested = ("auto","hcitool","bluez")[self.ble_index]
                self.ble_menu = False
            return
        if self.adapter_menu:
            rows=self.wifi_adapter_choices();self.adapter_index=min(self.adapter_index,len(rows)-1)
            if pressed & p.BTN_B:self.adapter_menu=False;self.scan_menu=True
            elif pressed & p.BTN_UP:self.adapter_index=(self.adapter_index-1)%len(rows)
            elif pressed & p.BTN_DOWN:self.adapter_index=(self.adapter_index+1)%len(rows)
            elif pressed & p.BTN_A:
                value=rows[self.adapter_index][0]
                if value=='__refresh__':self.adapter_refresh_requested=True;self.notice('Refreshing adapter list...')
                else:self.adapter_requested=value;self.adapter_menu=False
            return
        if self.scan_menu:
            if pressed & p.BTN_B:
                self.scan_menu = False
            elif pressed & p.BTN_UP:
                self.mode_index = (self.mode_index - 1) % (len(SCAN_MODES)+2)
            elif pressed & p.BTN_DOWN:
                self.mode_index = (self.mode_index + 1) % (len(SCAN_MODES)+2)
            elif pressed & p.BTN_A:
                if self.mode_index==len(SCAN_MODES):
                    self.adapter_requested='adaptive'
                elif self.mode_index==len(SCAN_MODES)+1:
                    self.adapter_menu=True;self.adapter_index=0;self.adapter_refresh_requested=True
                else:self.mode_requested = SCAN_MODES[self.mode_index]
                self.scan_menu = False
            return
        if self.confirm:
            if pressed & p.BTN_B:
                self.confirm = None
            elif pressed & p.BTN_A:
                if self.confirm == "EXIT":
                    self.exit_requested = True
                else:
                    if self.session.config.get("privacy_mode"):
                        self.confirm=None;self.notice("Turn Privacy off before excluding an address");return
                    self.session.exclude(self.detail.obs)
                    try:
                        self.on_save()
                        self.notice("Excluded from future observations")
                    except OSError as exc:
                        self.notice("Excluded this run; save failed: " + str(exc))
                    self.detail = None
                self.confirm = None
            return
        if self.detail:
            if pressed & p.BTN_B:
                self.detail=None
                return
            if self.session.config.get('privacy_mode') and pressed & (p.BTN_A|p.BTN_RIGHT):
                self.notice('Turn Privacy off to edit or track an address')
                return
            if pressed & p.BTN_RIGHT:
                self.hunt_key = self.detail.obs.protocol + ":" + self.detail.obs.address.upper()
                self.hunt_sound = False
                return
            if pressed & p.BTN_UP:
                self.offset = max(0, self.offset - 1)
            if pressed & p.BTN_DOWN:
                self.offset += 1
            if pressed & p.BTN_A:
                self.tools.open_device(self.contact_key(self.detail))
            return
        if pressed & p.BTN_LEFT:
            self.tab = (self.tab - 1) % len(self.tabs)
            self.index = 0
        if pressed & p.BTN_RIGHT:
            self.tab = (self.tab + 1) % len(self.tabs)
            self.index = 0
        if self.tab == 6 and pressed & (p.BTN_UP | p.BTN_DOWN):
            self.coverage_offset = max(0,self.coverage_offset + (1 if pressed & p.BTN_DOWN else -1))
            return
        if self.tab==7:
            self.tools.field_input(pressed)
            return
        if pressed & p.BTN_DOWN and self.tab == 4:
            self.diagnostic_view = True
            return
        if self.tab == 3 and pressed & (p.BTN_UP | p.BTN_DOWN | p.BTN_A):
            rows = self.radar_contacts(time.time())
            if pressed & p.BTN_A:
                self.radar_menu = True
                self.radar_menu_index = 0
            elif rows:
                index = next((i for i,d in enumerate(rows) if self.contact_key(d)==self.radar_selected),0)
                index = (index + (1 if pressed & p.BTN_DOWN else -1))%len(rows)
                self.radar_selected = self.contact_key(rows[index])
            return
        if pressed & p.BTN_UP and self.tab == 4:
            self.ble_index = ("auto","hcitool","bluez").index(self.session.config.get("ble_backend", "auto"))
            self.ble_menu = True
            return
        if pressed & p.BTN_UP:
            self.index = max(0, self.index - 1)
        if pressed & p.BTN_DOWN:
            self.index += 1
        if pressed & p.BTN_A and self.tab in (0, 1, 2):
            self.detail = self.selected()
            self.offset = 0
        if pressed & p.BTN_A and self.tab == 5:
            web = self.workers.get("Web")
            if web:
                try:
                    web.rotate_pin()
                    self.notice("New web code; browsers must sign in again")
                except OSError:
                    self.notice("Code changed; access file could not be saved")
        if pressed & p.BTN_A and self.tab == 4:
            mode = scan_mode(self.session.config)
            self.mode_index = SCAN_MODES.index(mode) if mode in SCAN_MODES else 0
            self.scan_menu = True
        if pressed & p.BTN_B or pressed & p.BTN_POWER:
            self.confirm = "EXIT"

    def draw(self, now=None):
        now = time.time() if now is None else now
        if self.splash_active:
            return
        p = self.p
        p.clear(p.hex_color(BG))
        self.box(0, 0, 480, 28, PANEL)
        self.text(8, 7, "PAGERWATCH", CYAN, 2)
        live = self.session.live(now)
        if self.hide_known:live=[d for d in live if not self.is_known(d)]
        self.text(234, 9, "LIVE WiFi %d  BLE %d" % (sum(d.obs.protocol == "wifi" for d in live),
                                                sum(d.obs.protocol == "ble" for d in live)), MUTED)
        for i, name in enumerate(self.tabs):
            self.text(8 + (480 // len(self.tabs)) * i, 34, "BT" if name == "BLUETOOTH" else name, CYAN if self.tab == i else MUTED)
        if self.tools.active:
            self.tools.draw(now)
        elif self.session.config.get('privacy_mode',False) and self.tab!=7:
            self.draw_private()
        elif self.tab==7:
            self.draw_field()
        elif self.diagnostic_view:
            self.draw_diagnostics(now)
        elif self.hunt_key:
            self.draw_hunt(now)
        elif self.detail:
            self.draw_detail(now)
        elif self.tab in (0, 1, 2):
            self.draw_list(now)
        elif self.tab == 3:
            self.draw_signal(live, now)
        elif self.tab == 6:
            self.draw_coverage()
        elif self.tab == 5:
            self.draw_web()
        else:
            self.draw_status()
        self.box(0, 202, 480, 20, PANEL)
        if self.tools.active:
            footer=self.tools.footer()
        elif self.tab==7:
            footer='UP/DN select  A apply  LEFT/RIGHT tabs  B finish'
        elif self.diagnostic_view:
            footer = "A export report   B back"
        elif self.hunt_key:
            footer = "A sound on/off   B details"
        elif self.detail:
            footer = "UP/DN scroll  RIGHT hunt  A actions  B back"
        elif self.tab == 3:
            footer = "UP/DN select  A actions  LEFT/RIGHT tabs  B finish"
        elif self.tab == 6:
            footer = "UP/DN channels   LEFT/RIGHT tabs   B finish"
        elif self.tab == 5:
            footer = "A new access code   LEFT/RIGHT tabs   B finish"
        elif self.tab == 4:
            footer = "UP BLE  DOWN diagnostics  A Wi-Fi  B finish"
        else:
            footer = "LEFT/RIGHT tabs   A details   B finish"
        self.text(8, 209, footer, MUTED)
        if now < self.notice_until:
            self.box(0, 181, 480, 19, 0x26443F)
            self.text(8, 187, 'Private notification' if self.session.config.get('privacy_mode',False) else self.last_notice, CYAN)
        if self.confirm:
            self.box(28, 66, 424, 99, PANEL)
            self.text(40, 80, "FINISH SESSION?" if self.confirm == "EXIT" else "EXCLUDE THIS ADDRESS?", CYAN, 2)
            self.text(40, 109, "Logs will be saved." if self.confirm == "EXIT" else "Existing logs stay; future sightings ignored.")
            self.text(40, 139, "A confirm                 B cancel", AMBER)
        if self.radar_menu:
            self.box(28, 48, 424, 150, PANEL)
            self.text(40, 58, "RADAR ACTIONS", CYAN, 2)
            choices = ["Device details", "Track selected signal", "Filter: "+(self.radar_filter or "all").upper(),
                       "Resume live view" if self.radar_snapshot is not None else "Freeze display (scan continues)"]
            for index,label in enumerate(choices):
                self.text(42, 86+index*21, ("> " if index==self.radar_menu_index else "  ")+label,CYAN if index==self.radar_menu_index else FG)
            self.text(40,181,"UP/DN select   A apply   B cancel",MUTED)
        if self.ble_menu:
            self.box(28, 48, 424, 150, PANEL)
            self.text(40, 58, "BLUETOOTH SCANNER", CYAN, 2)
            for index, label in enumerate(("Auto (hcitool first)", "hcitool / optional raw HCI", "BlueZ / bluetoothctl")):
                self.text(42, 91+index*25, ("> " if index == self.ble_index else "  ")+label,
                          CYAN if index == self.ble_index else FG)
            self.text(40, 181, "UP/DN select   A apply   B cancel", MUTED)
        if self.scan_menu:
            self.box(28, 48, 424, 150, PANEL)
            self.text(40, 58, "WI-FI SETTINGS", CYAN, 2)
            for index, mode in enumerate(SCAN_MODES):
                self.text(42, 80 + index * 16, ("> " if index == self.mode_index else "  ") + MODE_NAMES[mode],
                          CYAN if index == self.mode_index else FG)
            self.text(42,144,('> ' if self.mode_index==len(SCAN_MODES) else '  ')+'Auto-select Wi-Fi adapter',CYAN if self.mode_index==len(SCAN_MODES) else FG)
            self.text(42,160,('> ' if self.mode_index==len(SCAN_MODES)+1 else '  ')+'Manual adapter fallback...',CYAN if self.mode_index==len(SCAN_MODES)+1 else FG)
            self.text(40, 181, "UP/DN select   A apply   B cancel", MUTED)
        if self.adapter_menu:
            self.box(20,42,440,158,PANEL)
            self.text(32,53,'MANUAL WI-FI ADAPTER',CYAN,2)
            rows=self.wifi_adapter_choices();start=(self.adapter_index//5)*5
            for index,(_,label) in enumerate(rows[start:start+5],start):
                self.text(32,82+(index-start)*18,('> ' if index==self.adapter_index else '  ')+label[:57],CYAN if index==self.adapter_index else FG)
            self.text(32,180,'UP/DN select   A apply   B back',MUTED)
        p.flip()

    def draw_list(self, now):
        devices = self.list_devices()
        if not devices:
            message = "Listening for matching advertisements..." if self.tab == 0 else "No recent devices retained in this category yet."
            self.text(12, 75, message, MUTED)
            self.text(12, 101, "No match does not mean no device is present.", MUTED)
            self.text(12, 133, "Open STATUS to check scanner coverage.", CYAN)
            return
        self.index = min(self.index, len(devices) - 1)
        start = max(0, self.index - 3)
        for row, device in enumerate(devices[start:start + 4]):
            y = 54 + row * 35
            if start + row == self.index:
                self.box(5, y - 3, 470, 33, PANEL)
            obs = device.obs
            hit = device.hits[0] if device.hits else None
            color = RED if hit and hit.score >= 80 else AMBER if hit else FG
            local_address=bool(obs.address and len(obs.address)>=2 and int(obs.address[:2],16)&2)
            vendor = "" if local_address else device.vendor.get("name", "")
            note=self.session.config.get('device_notes',{}).get(obs.protocol+':'+obs.address,{})
            title = note.get('label') or (hit.label if hit else obs.name or fallback_name(device.bluetooth) or vendor or "Unnamed device")
            if obs.protocol=='wifi' and not note.get('label') and not hit and not device.ap_name:
                title=(vendor or 'Wi-Fi client') if not device.ap_seen and obs.frame=='probe_request' else 'Hidden SSID' if device.ssid_status=='hidden' else (vendor or 'SSID not captured')
            members = self.network_members(device) if self.tab == 1 else [device]
            suffix = " [%d radios]" % len(members) if len(members) > 1 else ""
            if self.tab == 1 and self.is_named_ap(device) and not note.get("label"):
                title = getattr(device,"ap_name","") or obs.name
            if note.get("bookmark"):title="* "+title
            if note.get("known"):title="K "+title
            self.text(10, y, title[:33-len(suffix)] + suffix, color, 2)
            age = max(0, int(now - obs.timestamp))
            rssi = "%s dBm" % obs.rssi if obs.rssi is not None else "RSSI ?"
            self.text(10, y + 19, "%s %s | %s | %ss ago | %s" % (
                obs.protocol.upper(), obs.address, rssi, age, hit.tier if hit else "unclassified"), MUTED)

    def draw_detail(self, now):
        d, obs = self.detail, self.detail.obs
        lines = [self.session.config.get('device_notes',{}).get(obs.protocol+':'+obs.address,{}).get('label') or obs.name or "(no advertised name)", obs.protocol.upper() + " " + obs.address,
                 "Latest RSSI: %s dBm | observations: %d" % (obs.rssi, d.seen),
                 "Average RSSI: %s dBm (%d fresh samples)" % (d.signal_average(now)["rssi_average"] if d.signal_average(now)["rssi_average"] is not None else "--",d.signal_average(now)["rssi_samples"]),
                 "Last seen: %ss ago | frame: %s" % (max(0, int(now - obs.timestamp)), obs.frame),
                 "Address type: " + obs.address_type,
                 "Frequency: " + str(obs.frequency or "not supplied")]
        if d.security:
            lines+=['Advertised: '+d.security.get('label','Unknown'),'PMF: '+d.security.get('pmf','Unknown')]
        if d.last_location:
            fix = d.last_location
            lines += ["LAST GPS SIGHTING: %.6f, %.6f" % (fix["lat"],fix["lon"]),
                      "Accuracy: %s m | sighting time: %s" % (fix.get("accuracy_m","?"),int(fix["observed_at"]))]
        if d.strongest_location:
            fix = d.strongest_location
            lines += ["STRONGEST GPS SIGHTING: %.6f, %.6f" % (fix["lat"],fix["lon"])]
        if obs.metadata_source == "hci_scan_cache":
            lines += ["HCI/name scan cache; field ages are bounded."]
        if obs.metadata_source == "bluez_cached_properties":
            lines += ["Includes BlueZ cached properties; not all are fresh ads."]
        members = self.network_members(d)
        if len(members) > 1:
            lines += ["SSID group: %d BSSIDs (may be distinct devices)" % len(members),
                      "Actions apply to this BSSID only; logs stay separate."]
            lines += ["BSSID %s | %s MHz | %s dBm" % (m.obs.address, m.obs.frequency or "?", m.obs.rssi) for m in members]
        if len(d.ssid_names)>1:
            lines += ["Recent names from this BSSID:"]
            for name in d.ssid_names:
                lines += textwrap.wrap(name,72)
        vendor = d.vendor
        lines += textwrap.wrap("MAC vendor: " + (vendor.get("name") or "not resolved"), 72)
        lines += ["Lookup: " + vendor.get("status", "unavailable") + " (not a product ID)"]
        for line in label_lines(d.bluetooth):
            lines += textwrap.wrap(line, 72)
        if d.bluetooth:
            lines += ["BLE labels are hints, not a confirmed device model."]
        for hit in d.hits:
            lines += [hit.tier + " / " + hit.label]
            lines += textwrap.wrap(hit.evidence, 72)
            lines += ["Rule: " + hit.rule]
        if not d.hits:
            lines += ["No matching rule; device identity unknown."]
        if obs.uuids:
            lines += ["UUID " + u for u in obs.uuids]
        lines += ["A match is not proof of recording, police presence,", "or a device's physical location."]
        self.offset = min(self.offset, max(0, len(lines) - 9))
        for index, line in enumerate(lines[self.offset:self.offset + 9]):
            self.text(9, 54 + index * 15, line, FG if index else CYAN)

    def draw_hunt(self, now):
        device = self.session.devices.get(self.hunt_key)
        if device is None:
            self.text(15, 75, "TARGET NO LONGER RETAINED", AMBER, 2)
            return
        obs = device.obs
        self.text(12, 55, (obs.name or obs.address)[:37], CYAN, 2)
        self.text(12, 80, obs.protocol.upper()+" "+obs.address, MUTED)
        samples = [(stamp,rssi) for stamp,rssi in device.history if 0 <= now-stamp]
        age = now-samples[-1][0] if samples else 0
        values = [rssi for stamp,rssi in samples if now-stamp <= 10]
        fresh = bool(values)
        wifi = self.workers.get("Wi-Fi")
        tracking = getattr(wifi,"tracking_status","Wi-Fi scanner unavailable") if obs.protocol == "wifi" else "Bluetooth: waiting for fresh advertisements"
        if not fresh:
            self.text(15, 108, "STALE: %s dBm" % samples[-1][1] if samples else "NO RSSI SAMPLE", AMBER, 3)
            self.text(15, 148, "Last measured %ds ago; not a live reading" % age if samples else "Waiting for a measured RSSI", MUTED)
            self.text(15, 170, tracking, MUTED)
            return
        rssi = round(device.signal_average(now)['rssi_average'])
        self.text(15, 104, "%d dBm" % rssi, CYAN, 4)
        self.box(15, 142, 450, 19, PANEL)
        self.box(17, 144, max(1,min(446,int((rssi+100)/70*446))), 15, CYAN)
        self.text(15, 171, tracking, MUTED)
        self.text(15, 187, "AVG %d | raw %s | %ds | sound %s" % (device.signal_average(now)["rssi_samples"],samples[-1][1],age,"ON" if self.hunt_sound else "OFF"), MUTED)
        if self.hunt_sound and self.session.config.get('scan_profile')!='quiet' and now-self.hunt_feedback >= max(0.5, min(3,(-rssi-25)/25)):
            self.hunt_feedback = now
            try:
                self.p.beep(500+max(0,min(1200,(rssi+100)*15)),20)
            except (AttributeError,OSError):
                pass

    @staticmethod
    def contact_key(device):
        return device.obs.protocol+":"+device.obs.address.upper()

    def radar_contacts(self, now):
        devices = list(self.session.devices.values()) if self.radar_snapshot is None else list(self.radar_snapshot)
        if self.hide_known:devices=[d for d in devices if not self.is_known(d)]
        if self.radar_filter:
            devices = [d for d in devices if d.obs.protocol == self.radar_filter]
        return sorted(devices,key=lambda d:(-(d.hits[0].score if d.hits else 0), -(d.obs.rssi if d.obs.rssi is not None else -999),self.contact_key(d)))

    @staticmethod
    def radar_signal(device):
        return device.history[-1][1] if device.history else device.obs.rssi

    def draw_signal(self, devices, now=None):
        p = self.p
        now = time.time() if now is None else now
        # Respect direct callers passing a device list, including preview tests.
        rows = self.radar_contacts(now) if self.session is not None else list(devices)
        keys = {self.contact_key(d) for d in rows}
        if self.radar_selected not in keys:
            self.radar_selected = self.contact_key(rows[0]) if rows else None
        selected_index = next((i for i,d in enumerate(rows) if self.contact_key(d)==self.radar_selected),0)
        cx,cy,radius = 87,128,61
        grid = p.hex_color(0x244417)
        for r in (20,40,61):
            p.circle(cx,cy,r,grid)
        p.line(cx-radius,cy,cx+radius,cy,grid)
        p.line(cx,cy-radius,cx,cy+radius,grid)
        sweep = (now%6)/6*math.tau
        for offset,color in ((.30,0x17350A),(.20,0x295611),(.10,0x4D8D13),(0,CYAN)):
            angle=sweep-offset
            p.line(cx,cy,int(cx+math.cos(angle)*radius),int(cy+math.sin(angle)*radius),p.hex_color(color))
        plotted = rows[:24]
        chosen = next((d for d in rows if self.contact_key(d)==self.radar_selected),None)
        if chosen and chosen not in plotted:
            plotted=plotted[:23]+[chosen]
        for d in plotted:
            angle=int.from_bytes(hashlib.sha256(self.contact_key(d).encode()).digest()[:2],"big")/65536*math.tau
            value=self.radar_signal(d)
            distance=radius if value is None else max(7,min(radius,int((-value-25)/75*radius)))
            x,y=int(cx+math.cos(angle)*distance),int(cy+math.sin(angle)*distance)
            stale=now-(d.history[-1][0] if d.history else d.obs.timestamp)>10
            if value is None:p.circle(x,y,3,p.hex_color(CYAN))
            else:p.fill_circle(x,y,3,p.hex_color(0x48752B if stale else CYAN))
            if self.contact_key(d)==self.radar_selected:
                p.circle(x,y,6,p.hex_color(CYAN))
        self.text(12,55,(self.radar_filter or "ALL").upper()+" / %d"%len(rows),CYAN)
        self.text(12,190,"SESSION / dim=old",MUTED)
        if self.radar_snapshot is not None:
            self.text(12,70,"FROZEN VIEW",AMBER)
        if not rows:
            self.text(178,83,"No session contacts",MUTED,2)
            self.text(178,115,"Open STATUS for scanner health.",MUTED)
            return
        start=max(0,selected_index-3)
        for index,d in enumerate(rows[start:start+4]):
            y=55+index*34
            selected=self.contact_key(d)==self.radar_selected
            if selected:
                self.box(168,y-2,306,32,PANEL)
            title=self.radar_label(d)
            self.text(175,y,("> " if selected else "  ")+title[:22],CYAN if selected else FG,2)
            samples=[value for stamp,value in d.history if 0<=now-stamp<=15]
            delta=int(statistics.median(samples[-3:])-statistics.median(samples[-6:-3])) if len(samples)>=6 else None
            trend=("%+ddB"%delta) if delta is not None else "--"
            self.text(175,y+19,"%s %s dBm %s %ds %s"%(d.obs.protocol.upper(),self.radar_signal(d) if self.radar_signal(d) is not None else "?",trend,
                      max(0,int(now-d.obs.timestamp)),d.hits[0].tier if d.hits else ""),MUTED)
        self.text(176,193,"%d/%d  A actions"%(selected_index+1,len(rows)),CYAN)

    def draw_diagnostics(self, now):
        worker=self.workers.get("BLE")
        metrics=dict(getattr(worker,"metrics",{}))
        candidates=list(getattr(worker,"candidates",{}).values())
        ble=[d for d in self.session.live(now) if d.obs.protocol=="ble"]
        recent=metrics.get("last_observation",0)
        age="never" if not recent else "%ds"%max(0,int(now-recent))
        lines=["BLUETOOTH DIAGNOSTICS",
               "Backend: %s | controller: %s"%(metrics.get("backend","unknown"),metrics.get("controller","unknown")),
               "Receiver: "+metrics.get("receiver","unknown"),
               "RX: %s socket packets / %s reports / %s names"%(metrics.get("raw_packets",0),metrics.get("decoded_reports",0),metrics.get("name_lines",0)),
               "Live BLE: %d | last received: %s"%(len(ble),age),
               "Flipper hints: %d session / %d cache-only"%(len(candidates),len(getattr(worker,"cached_candidates",[])))]
        if candidates:
            obs=candidates[-1]["observation"]
            key="BLE:"+obs["address"].upper()
            ignored=obs["address"].upper() in self.session.excluded or key in self.session.excluded
            lines.append("Latest: "+obs["address"]+(" [EXCLUDED]" if ignored else ""))
        else:
            lines.append("No Flipper signature observed; absence is inconclusive.")
        status=getattr(worker,"status","Bluetooth worker unavailable")
        error=status if status.startswith("ERROR") else metrics.get("last_error") or status
        health=getattr(getattr(worker,'receive_health',None),'snapshot',lambda:{})()
        reports=health.get('reports',{}).get('age_seconds');metadata=health.get('metadata',{}).get('age_seconds')
        lines.insert(1,'Recent reports: %s / metadata: %s'%('never' if reports is None else str(int(reports))+'s', 'never' if metadata is None else str(int(metadata))+'s'))
        lines.append(("Exporting report..." if self.export_busy else error)[:76])
        for index,line in enumerate(lines[:9]):
            self.text(9,54+index*16,line,CYAN if index==0 else FG)

    def draw_private(self):
        self.text(20,65,'PRIVACY MODE',CYAN,3)
        self.text(20,105,'Names, addresses and GPS hidden on screen.',FG)
        self.text(20,128,'Scanning and original records continue.',MUTED)
        self.text(20,151,gps_health(self.session.gps_status)[:70],FG)
        self.text(20,178,'FIELD tab: profiles / privacy / storage',CYAN)

    def draw_field(self):
        self.tools.draw_field()

    def draw_status(self):
        lines = ["Mode: " + MODE_NAMES.get(scan_mode(self.session.config), "Custom") + " | A mode / adapter"]
        for name, worker in self.workers.items():
            lines += textwrap.wrap(name + ": " + worker.status, 74)
        lines += ["Addresses: %d | evicted: %d | observations: %d" % (
                      len(self.session.devices), self.session.evicted, self.session.events),
                  self.session.vendor_status, self.session.bluetooth_status, "Logs: local only / no uploads", "Session: " + self.session.path.name]
        if self.session.log_error:
            lines = [self.session.log_error] + lines
        if getattr(self.session,"checkpoint_error",""):lines=[self.session.checkpoint_error]+lines
        for i, line in enumerate(lines[:9]):
            self.text(9, 55 + i * 16, line, AMBER if "ERROR" in line else FG)

    def draw_web(self):
        web = self.workers.get("Web")
        if not web:
            self.text(12, 63, getattr(self.session,"web_error","Web dashboard disabled"), AMBER)
            return
        self.text(12, 58, web.status, CYAN)
        self.text(12, 77, web.url or "Preparing HTTPS certificate...", CYAN, 2)
        self.text(12, 104, "ACCESS CODE: " + web.pin, CYAN, 2)
        gps = web.phone.status()
        location = "Phone GPS: no fresh fix"
        if gps["valid"]:
            location = "Phone GPS: +/- %dm   age %.0fs" % (gps["accuracy_m"],gps["age_seconds"])
        self.text(12, 132, location, MUTED)
        self.text(12, 150, "CA SHA256 (verify before trusting certificate):", MUTED)
        fingerprint = web.fingerprint or "Not available"
        self.text(12, 166, fingerprint[:32], MUTED)
        self.text(12, 180, fingerprint[32:], MUTED)

    def draw_coverage(self):
        worker=self.workers.get("Wi-Fi")
        coverage=getattr(worker,"coverage",None)
        if not coverage:
            self.text(12,65,"Wi-Fi coverage unavailable",AMBER)
            return
        data=coverage.snapshot();rows=data["channels"]
        self.text(10,54,"SELECTED %d/%d  RX %d  REJECT %d" % (data["visited"],data["planned"],data["decoded_frames"],data["rejected"]),CYAN)
        self.text(10,70,getattr(worker,"status","Not available"),MUTED)
        self.coverage_offset=min(self.coverage_offset,max(0,len(rows)-6))
        for index,row in enumerate(rows[self.coverage_offset:self.coverage_offset+6]):
            selected=row["frequency"]==data["current_frequency"]
            color=AMBER if row["rejected"] else CYAN if selected else FG
            self.text(10,91+index*16,(">" if selected else " ")+"%s MHz  visits:%d  frames:%d  reject:%d" % (row["frequency"],row["visits"],row["frames"],row["rejected"]),color)
        if not rows:self.text(10,106,"No frequency plan / receive metadata available yet",MUTED)
        self.text(10,190,"Selections / received observations, not airtime",MUTED)
