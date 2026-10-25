# PagerWatch 1.0.8 — Wardrive Go probe detection

- Add the complete 32-prefix wildcard-probe heuristic from RocketGod's Wardrive Go classifier, pinned to revision b30f16fb3b31807b2526678db2de12c377e09ff6. This adds 31 prefixes alongside the existing Flock Safety prefix in that detection path.
- Show shared-prefix matches as **Possible Flock wildcard probe**. The default alert threshold (75) includes this candidate; it is not proof of a camera or a Flock-owned MAC registration.
- Distinguish a real zero-length probe SSID from directed, missing, duplicate or truncated SSID fields. Requested network names are not treated as device names.
- Include probe type in the classification cache so a later wildcard probe is evaluated even if the MAC/name are unchanged.
- Strip an included frame checksum according to radiotap flags; reject frames marked BADFCS.
- Keep 1.0.7 MAC normalization, public Bluetooth matching and passive management-frame coverage. USB handling and other recon features are unchanged.

## Update from Windows

Finish PagerWatch. Extract `PagerWatch-1.0.8-release.zip`. In WinSCP, copy the complete `PagerWatch` folder into `/root/payloads/user/reconnaissance/`, replacing matching release files. Keep `config.json` and `.state`. Relaunch and refresh the dashboard.

Host tests validate synthetic packets and regression behavior. The local camera's exact MAC/protocol has not been supplied; field detection is not yet verified. Shared-chipset candidates can also match ordinary devices. Compare Devices as well as Alerts; thresholds and filters may suppress an alert.
