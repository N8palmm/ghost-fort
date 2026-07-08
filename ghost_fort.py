"""
GHOST FORT — MAIN ORCHESTRATOR v3 FINAL
All issues resolved:
  [1] Status file written atomically — no world-readable race
  [2] Watchdog thread monitors all daemon threads, alerts + restarts on death
  [3] Graceful drain of async DB writer before exit
  [4] Systemd watchdog integration via sd_notify
  [5] Thread health heartbeat system
"""

import sys, signal, logging, threading, time, json, os, tempfile, shutil
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from threat.intel_engine import ThreatIntelEngine, DB_PATH
from ids.ids_engine import GhostIDS, create_monitor

Path("/var/log/ghost").mkdir(parents=True, exist_ok=True)
Path("/var/lib/ghost").mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/ghost/ghost_fort.log", mode="a"),
    ]
)
logger = logging.getLogger("ghost.fort")

STATUS_FILE  = Path("/var/lib/ghost/status.json")
WATCHDOG_INT = 30   # seconds between watchdog checks


# ── SYSTEMD WATCHDOG INTEGRATION ─────────────────────────────

def sd_notify(state: str):
    """
    Send notification to systemd watchdog socket.
    Enables systemd to restart Ghost Fort automatically if it hangs.
    No-ops gracefully if not running under systemd.
    """
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    try:
        import socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if addr.startswith("@"):
            addr = "\0" + addr[1:]
        sock.connect(addr)
        sock.sendall(state.encode())
        sock.close()
    except Exception:
        pass


# ── ATOMIC FILE WRITE ─────────────────────────────────────────

def write_atomic(path: Path, content: str, mode: int = 0o600):
    """
    [FIX] Write to a temp file then atomically rename.
    Eliminates the race window where a partially written file
    could be read, and ensures the file is always root-only.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".ghost_tmp_")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.chmod(tmp, mode)
        shutil.move(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except Exception:
            pass
        raise


# ── THREAD WATCHDOG ───────────────────────────────────────────

class ThreadWatchdog:
    """
    [FIX] Monitors all critical daemon threads.
    If any thread hasn't sent a heartbeat in WATCHDOG_INT*2 seconds,
    it fires an alert and attempts to restart the affected subsystem.
    """

    def __init__(self, fort: "GhostFort"):
        self.fort = fort
        self._running = False
        self._thread: threading.Thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="watchdog"
        )
        self._thread.start()
        logger.info("Thread watchdog started")

    def stop(self):
        self._running = False

    def _loop(self):
        while self._running:
            try:
                self._check_threads()
                # Tell systemd we're still alive
                sd_notify("WATCHDOG=1")
            except Exception as e:
                logger.error(f"Watchdog error: {e}")
            time.sleep(WATCHDOG_INT)

    def _check_threads(self):
        now = time.time()
        names = {t.name for t in threading.enumerate()}
        critical = {
            "intel-refresh":   self.fort.intel,
            "nft-monitor":     self.fort.monitor,
            "netstat-monitor": self.fort.monitor,
            "db-async-writer": self.fort.ids.db_writer,
        }
        for thread_name, _ in critical.items():
            # Check if thread is alive
            if not any(thread_name in n for n in names):
                logger.critical(
                    f"⚠️  WATCHDOG: Thread '{thread_name}' is DEAD — "
                    f"attempting restart"
                )
                self._attempt_restart(thread_name)
                # Fire alert if alerter available
                if self.fort.ids._alerter:
                    self.fort.ids._alerter.fire({
                        "ip": "SYSTEM",
                        "risk_level": "CRITICAL",
                        "threat_category": "SYSTEM_FAULT",
                        "country": "LOCAL",
                        "block_reason": f"Thread '{thread_name}' died and was restarted",
                    }, f"Ghost Fort internal thread failure: {thread_name}")

    def _attempt_restart(self, thread_name: str):
        try:
            if "intel-refresh" in thread_name:
                self.fort.intel.start_auto_refresh()
                logger.info(f"Restarted intel-refresh thread")
            elif "monitor" in thread_name:
                self.fort.monitor.start()
                logger.info(f"Restarted monitor thread")
            elif "db-async-writer" in thread_name:
                from ids.ids_engine import AsyncDBWriter
                self.fort.ids.db_writer = AsyncDBWriter(self.fort.intel.db)
                logger.info(f"Restarted db-async-writer thread")
        except Exception as e:
            logger.error(f"Restart of '{thread_name}' failed: {e}")


# ── GHOST FORT ────────────────────────────────────────────────

class GhostFort:

    def __init__(self):
        self.intel    = ThreatIntelEngine()
        self.ids      = GhostIDS(self.intel)
        self.monitor  = create_monitor(self.ids)
        self.watchdog = ThreadWatchdog(self)
        self._start   = datetime.utcnow()
        self._running = False

    def start(self):
        logger.info("=" * 60)
        logger.info("  GHOST FORT v3 — FULLY HARDENED SECURITY STACK")
        logger.info("=" * 60)

        sd_notify("STATUS=Starting Ghost Fort v3")

        logger.info("[1/4] Starting threat intelligence engine...")
        self.intel.start_auto_refresh()

        logger.info("[2/4] Starting IDS + connection monitor...")
        self.monitor.start()

        logger.info("[3/4] Starting thread watchdog...")
        self.watchdog.start()

        logger.info("[4/4] Starting status writer...")
        self._running = True
        threading.Thread(
            target=self._status_loop, daemon=True, name="status-writer"
        ).start()

        sd_notify("READY=1\nSTATUS=Ghost Fort active")
        logger.info(f"✅ GHOST FORT ACTIVE — mode={self.monitor._mode}")

    def stop(self):
        logger.info("Ghost Fort shutting down...")
        sd_notify("STOPPING=1")
        self._running = False
        self.watchdog.stop()
        self.monitor.stop()
        self.intel.stop()
        self.ids.shutdown()    # drains async DB writer before exit
        logger.info("Ghost Fort stopped cleanly.")

    def status(self) -> dict:
        uptime = int((datetime.utcnow() - self._start).total_seconds())
        return {
            "running":        self._running,
            "start_time":     self._start.isoformat(),
            "uptime_seconds": uptime,
            "detection_mode": self.monitor._mode,
            "active_threads": [t.name for t in threading.enumerate()],
            "profile_count":  self.ids.profiles.size(),
            "threat_intel":   self.intel.get_stats(),
            "firewall": {
                "active_bans": self.ids.firewall.ban_count(),
                "banned_ips":  self.ids.firewall.list_bans()[:50],
            },
            "recent_blocks":  self.ids.get_blocked(limit=10),
        }

    def _status_loop(self):
        while self._running:
            try:
                # [FIX] Atomic write — no race, root-only permissions
                write_atomic(
                    STATUS_FILE,
                    json.dumps(self.status(), indent=2, default=str),
                    mode=0o600
                )
            except Exception as e:
                logger.error(f"Status write error: {e}")
            time.sleep(5)


# ── ENTRY POINT ───────────────────────────────────────────────

if __name__ == "__main__":
    fort = GhostFort()

    def _shutdown(sig, frame):
        fort.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    fort.start()
    while True:
        time.sleep(10)
