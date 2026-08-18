## 2026-08-18 — SIEM & Dashboard Hardening

**Problem:** Splunk and the Ghost Fort web dashboard were both bound to
`0.0.0.0`, listening on all interfaces by default rather than being
explicitly scoped. The dashboard was also running on Flask's built-in
development server, which is explicitly unsupported for
production/always-on use.

**Changes:**
- Restricted Splunk (splunkd + Splunk Web) to loopback-only via
  `SPLUNK_BINDIP=127.0.0.1` in `splunk-launch.conf`, with matching
  `mgmtHostPort` in `web.conf` to keep the web UI able to reach splunkd.
- Replaced the Flask development server with `gunicorn` (2 workers),
  bound to `127.0.0.1:5000`, managed via systemd for automatic restart.
- Fixed ownership of the Python venv (`/opt/ghost-fort/venv`) to allow
  package management without elevated privileges going forward.

**Result:** Both services remain fully accessible locally (via WSL2's
loopback forwarding to the Windows host) but are no longer reachable
from the LAN or any other device — verified by direct connection test
from a separate device on the same network. No functionality lost;
attack surface reduced.

**Backlog:** `ghost-dashboard.service` currently runs as `root` — needs
file-ownership audit across `/opt/ghost-fort` before safely dropping to
a lower-privilege user.
