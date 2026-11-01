![PagerWatch — by Nester](assets/github-banner.png)

# PagerWatch

**Wi-Fi & Bluetooth reconnaissance for the WiFi Pineapple Pager · by Nester**

Discover nearby radios, inspect device signatures, track signals and save GPS-tagged sightings. Use the Pager's display in the field or open the dashboard on your phone or laptop.

[Install](#install) · [How to use](#how-to-use) · [Latest changes](RELEASE-NOTES.md) · [Credits](NOTICE.md)

## Features

- **Wi-Fi & Bluetooth discovery** — separate device lists, signal history and manufacturer lookup.
- **Device alerts** — Flock, Axon, Flipper Zero, tracker and other signature clues, with evidence for each match.
- **Radar & tracking** — retained session contacts, optional recent/live views, stale-signal labels and channel hold for a selected Wi-Fi target.
- **USB adapters** — automatic USB selection and Pager fallback, with manual selection when needed.
- **Phone GPS** — coordinates, speed, heading and location tags for new sightings.
- **Device research** — notes, photos, labels, bookmarks, watchlists and past sightings.
- **Saved sessions** — review, compare and export findings as CSV, JSONL, GeoJSON or HTML reports.
- **Privacy mode** — hide names, addresses and location details on screen.
- **Field tools** — Survey, Track and Quiet profiles, known-gear filtering, radio health and storage status.
- **Recovery & backups** — interrupted-session checkpoints and settings backup/restore.

## Install

1. Download **PagerWatch-1.0.11-release.zip** from **Releases** and extract it on your Windows PC.
2. Connect your PC to the Pager and open **WinSCP**.
3. Connect using **SCP**, host **`172.16.52.1`**, port **`22`**, username **`root`** and your Pager's root password. Use its actual IP if different.
4. In WinSCP, open **`/root/payloads/user/reconnaissance/`** on the Pager.
5. **Drag and drop the entire extracted `PagerWatch` folder** into that directory.
6. On the Pager, launch **Payloads → User → Reconnaissance → PagerWatch**. Press **A** past the startup image.

Copy the whole folder, not just `payload.sh` or the ZIP. Startup checks attempt to install missing supported dependencies; the Pager needs internet access for package downloads. USB adapters need compatible drivers.

**Updating:** finish the running payload, replace matching release files and keep `config.json` and `.state`. Copy the complete release folder, then relaunch.

## How to use

1. **Start scanning.** Browse Wi-Fi, Bluetooth, radar and status on the Pager.
2. **Open the dashboard.** Connect your phone or laptop to Pager Wi-Fi. Open the HTTPS address shown on **WEB**—normally `https://172.16.52.1:8443`—and enter the displayed six-digit code.
3. **Share GPS.** Open **Phone GPS → Share this device's GPS**. Allow location and wait for a fresh fix. Keep the phone connected, awake and the page open.
4. **Inspect devices.** Open **Devices** to track a signal, add a label/bookmark or review research and past sightings.
5. **Save your results.** Use **Sessions** to review runs and **Controls & exports** to download reports, manage adapters or back up settings.

**Pager buttons:** Left/Right changes tabs; Up/Down selects or scrolls; **A** opens/applies; **B** goes back. Open **FIELD** for run summaries, GPS, known gear and saved runs. In device details, **A** opens actions.

## New in 1.0.11

- Keep radar contacts throughout the retained session inventory. Switch to recent (5 minutes) or live (30 seconds) when wanted. Older measurements are dimmed; unknown signal strength uses a hollow edge marker.
- Keep recorded signature evidence when later packets omit a name or service. Device details show when the signature was last observed; original packet logs remain separate.
- Enable default-threshold alerts for Tile services and supported Apple Find My records, including short forms. AirTag-compatible status is identified as a signature, not a verified product.
- Recover Bluetooth names-only reception at startup or mid-session in Auto mode. Scanner cards show recent receive ages.
- Explain a missed detection in **Alerts → Why wasn’t this detected?**, or the Pager device-actions menu. Checks use recorded evidence and never force another alert.
- Export rule version/hash, recent detection checks and bounded advertisement samples with diagnostics.

## Responsiveness

Version 1.0.11 prioritizes Pager input, queues short button taps, moves vibration and checkpoint writes off the control loop, and splits dashboard snapshots into small work slices. Repeated identical Bluetooth bursts are combined; changed detection evidence passes immediately. Recorded alerts remain once per protocol/address per session.

Check **Overview → Field reliability** for the longest control-loop gap and slow-turn count. These help investigate remaining lag; actual Pager responsiveness still needs field testing.

## Good to know

- Signature matches are clues, not confirmed identities. Shared-prefix wildcard probes appear as **Possible Flock**; ordinary devices can also match. Detection depends on receiving a device's transmissions.
- GPS marks where the receiver heard a device, not the device's exact position. Phone browsers do not provide satellite counts.
- Privacy masks the screen. Exports, backups and API responses retain original data. No automatic uploads or online research lookups are performed.
- Leave adapter selection on **Auto** for USB-to-Pager fallback. A manually selected adapter stays pinned.

[Release notes](RELEASE-NOTES.md) · [Hardware test checklist](FIELD-TEST.txt) · [GPL-3.0-or-later](LICENSE)

---

Created by **Nester**, with development help from **ChatGPT**. Thanks to **RocketGod**, **Hackazillarex** and the contributors whose shared work helped make PagerWatch possible. See [credits and licenses](NOTICE.md).

Detection troubleshooting: compare the exact MAC and radio type in the new check before changing rules. A missing retained contact is different from a received address with no matching signature. Quiet RF does not establish a receiver fault. Diagnostic downloads contain original identifiers even when Privacy hides them on screen.
