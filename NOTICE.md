# Credits & licenses

**PagerWatch · by Nester**

Special thanks to **RocketGod**, **Hackazillarex**, and the developers and researchers whose shared work helped make PagerWatch possible. **ChatGPT** assisted with development, troubleshooting and documentation.

PagerWatch is an independent community project, not an official Hak5 or Wardrive Go release. Original PagerWatch code and independently implemented rules use **GPL-3.0-or-later**; see [LICENSE](LICENSE). Third-party files retain their original licenses.

## Bundled code and data

| Project | Included material | License / source |
| --- | --- | --- |
| **pagerctl — brAinphreAk** | `lib/pagerctl.py`, `lib/libpagerctl.so`, and corresponding source, headers, Makefile and README in `third_party/pagerctl/`. | MIT; [permission notice](third_party/PAGERCTL-MIT.txt). [Source](https://github.com/pineapple-pager-projects/pineapple_pager_pagerctl), revision `30ef1028500ba1d0303d24ea5d62497407bac77d`. Upstream dependency files remain unmodified; embedded headers retain their notices. |
| **Wardrive Go — RocketGod and contributors** | Unchanged `oui_manuf.txt` and `ble_vendor_data.json` snapshots in `third_party/wardrive-go/`. The Wi-Fi lookup index is derived from that directory. | [GPL-3.0](third_party/wardrive-go/LICENSE). [Source](https://github.com/RocketGod-git/wardrive-go), revision `b30f16fb3b31807b2526678db2de12c377e09ff6`. Original paths: `app/src/main/assets/oui_manuf.txt` and `app/src/main/assets/ble_vendor_data.json`. Hashes and snapshot metadata are retained in `data/oui_source.json` and `data/ble_source.json`. The wildcard-probe prefix set and predicate in `rules.json` are adapted from `app/src/main/java/com/rocketgod/warble/classify/NotableDevices.kt` at the same revision. Shared-prefix matches are presented as candidates. No upstream Kotlin implementation or icons are bundled. |
| **Go standard library/runtime** | Runtime linked into `lib/pw-certgen-mipsle`, the local certificate generator. | [BSD license](third_party/GO-LICENSE). PagerWatch helper source is in `source/certgen/main.go` under GPL-3.0-or-later. |

The certificate helper was built with Go 1.27.2 for `linux/mipsle`, soft-float, CGO disabled, with trimmed paths and stripped symbols. It generates individual CA/server keys on the Pager; no shared private key is bundled.

## Detection research

Rules are independently implemented except for the credited Wardrive Go wildcard-probe prefix set and predicate adaptation above. Each entry in `rules.json` retains its source URL. Manufacturer labels identify a registrant or shared component; scores are not measured detection probabilities.

| Reference | Contribution |
| --- | --- |
| [all-cameras-are-beacons — soyboi1312 and contributors](https://github.com/soyboi1312/all-cameras-are-beacons) | Signature references and false-positive research. Revision `a54bf934591ef3e9cc9187327d0d88b2f887da3b`; [Apache-2.0 license retained](third_party/ACAB-LICENSE). |
| [RF Sentinel — CIS-C0 and contributors](https://github.com/CIS-C0/RFSentinel) | Flock accessory UUIDs, company IDs, Axon pairing names and tracker references. GPL-3.0; revision `a9a5b615499b49a34abf940ddad3e3c507840972`. No Kotlin implementation is bundled. |
| [Flipper Zero firmware — Flipper Devices](https://github.com/flipperdevices/flipperzero-firmware/tree/3fb1d51727733d2007abc5ec636a89328857803e) | Advertised service variants, names and address construction. No firmware implementation is included. |
| [Bluetooth SIG Assigned Numbers](https://www.bluetooth.com/specifications/assigned-numbers/) and [IEEE Registration Authority](https://regauth.standards.ieee.org/) | Company/service identifiers and address-prefix context. |

## Community payload references

The following projects informed design and compatibility work. Their payload implementations are not copied or launched by PagerWatch.

From [Hak5's Pager payload repository](https://github.com/hak5/wifipineapplepager-payloads), revision `5ed2f6c307880c9201c0f7912da6076caa5cc1d7`:

| Payload | Author(s) | Reference area |
| --- | --- | --- |
| `device_hunter` | RocketGod, NotPike | Target selection and signal feedback. |
| `Flock_Detect` | colonelpanichacks and contributors | Bluetooth tool compatibility and accessory-name hints. |
| `find_hackers` | NULLFaceNoCase | Flipper/name/address hints and Wi-Fi identity handling. |
| `flipper_detector` | nemanjan00 | Flipper candidate diagnostics; shared prefixes remain weak hints. |
| `mobile2gps` | ryanpohlner and contributors | Browser GPS sharing and optional gpsd integration; GPL-3.0 reference. No Go server or HTML from it is bundled. |
| `external-mediatek-radio-loader` | Huntz | Onboard/external radio distinction and physical-device exclusion. |
| `AntennaCheka` | Notorious Squirrel | Radio identification conventions. |

Additional references at revision `1a433aa9d172d77a9af947949e56bfbcbb6f5c88`: **SignalFence** (4c1d.burn), **Bluetooth Device Hunter** (cncartist), **ReconDB Reporting** (Digs), and **Blue Clues / ProbeHound** (Doc Voom). These informed coverage, reporting and device-context design. [WDGoWars — LOCOSP](https://github.com/LOCOSP/pineapple_pager_wdgwars) was reviewed for Pager platform conventions; no files were copied.

## Technical references & artwork

Radio and browser integrations use the [Linux Wireless iw documentation](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw.html), [virtual-interface documentation](https://wireless.docs.kernel.org/en/latest/en/users/documentation/iw/vif.html), [Linux HCI socket structures](https://github.com/torvalds/linux/blob/master/include/net/bluetooth/hci_sock.h), BlueZ tool documentation, [browser Geolocation API](https://developer.mozilla.org/en-US/docs/Web/API/Geolocation_API), and [gpsd documentation](https://gpsd.io/gpsd.html).

`assets/startup.png` is the AI-generated PagerWatch artwork approved by Nester and included unchanged. No ownership claim or software-license grant is made for third-party trademarks. No Google SDK, map tiles, chipset drivers or firmware are bundled.

## Field tools (0.5.0)

The archive browser, labels/watch rules, health indicators, profiles and screen privacy are independently implemented GPL-3.0-or-later. The bounded RSN/WPA parser uses public information-element layouts and selector identifiers, cross-checked against the hostap project headers: https://w1.fi/wpa_supplicant/devel/wpa__common_8h_source.html and https://android.googlesource.com/platform/external/wpa_supplicant_8/+/d04654c0420f21baf5f162dafd13b1c01893e3d0/src/common/wpa_common.h . No hostap implementation code is copied. Displayed security describes advertisements. No vulnerability verdict is included.


## Reliability and dependency setup (1.0.3)

Automatic setup uses the Pager's existing opkg feeds. Package names and split-library behavior were checked against the official OpenWrt 24.10 [Python package](https://github.com/openwrt/packages/blob/openwrt-24.10/lang/python/python3/Makefile), [BlueZ package](https://github.com/openwrt/packages/blob/openwrt-24.10/utils/bluez/Makefile), and [mt76 kernel packages](https://github.com/openwrt/openwrt/blob/openwrt-24.10/package/kernel/mt76/Makefile). The MediaTek USB identifier and internal-device exclusion approach were reviewed against Huntz's External MediaTek Loader in the Hak5 payload repository. No loader source was copied or firmware feeds added. Runtime dependencies and drivers are resolved by opkg and retain their upstream licenses; none are bundled here.
