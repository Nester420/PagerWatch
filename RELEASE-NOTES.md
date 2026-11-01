# PagerWatch 1.0.11 — Pager responsiveness

- Check physical input before scan processing. Use queued press/release events when pagerctl supports them, preserving short taps and repeated direction presses; retain the legacy input fallback.
- Run alert vibration in one bounded background worker. Burst feedback is rate limited to one pulse per two seconds; individual matching addresses still receive their recorded alerts.
- Prepare recovery inventories in small pieces and write/sync checkpoints in the background. Interrupted-session review replays journal changes received during preparation without overwriting newer inventory evidence.
- Build dashboard snapshots in small pieces and publish each completed snapshot atomically.
- Limit scan processing to short work slices and target a 40 ms control-loop interval. This is a scheduling target, not a hardware latency guarantee.
- Combine redundant Bluetooth bursts for up to 500 ms. Changed advertised evidence and RSSI changes of at least 4 dB pass immediately; periodic updates continue. Raw receive counters still count incoming advertising reports.
- Avoid repeatedly rebuilding identical diagnostic samples. Add longest control-loop gap and slow-turn counts to dashboard reliability details and diagnostics.

## Install / update from Windows

Finish PagerWatch. Extract `PagerWatch-1.0.11-release.zip`. In WinSCP use SCP and copy the complete `PagerWatch` folder into `/root/payloads/user/reconnaissance/`, replacing release files. Preserve `config.json` and `.state`. Relaunch and refresh the dashboard.

## Test this build on the Pager

Compare the same location, adapter and display tab against 1.0.10. Try short direction-button taps and opening/backing out of device actions with the phone dashboard both connected and disconnected. Run for at least 20 minutes so several checkpoints occur. Check Bluetooth alerts, USB fallback, GPS-tagged logging and saved-session exports. If lag returns, build diagnostics immediately and record the tab, elapsed runtime, active adapter and whether the dashboard was connected.

Host tests simulate button queues, slow storage, burst reception and interrupted checkpoint recovery. Actual display latency, radio load and storage behavior require Pager testing. Features, saved settings and existing logs are retained. No handshake capture or deauthentication is included.
