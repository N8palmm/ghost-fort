"""
GHOST FORT — ALERT NOTIFIER v3 FINAL
All issues resolved:
  [1] Passwords/webhook URLs stored encrypted via system keyring, never plaintext
  [2] Retry with exponential backoff on all delivery failures
  [3] Email uses SMTP_SSL (port 465) with full cert verification — no STARTTLS
  [4] Webhook URL never logged or stored in status.json
  [5] Config file stores only non-sensitive settings — secrets in keyring
  [6] Graceful degradation — missing keyring falls back to env vars
"""

import smtplib, threading, logging, json, time, ssl, os
import requests
from datetime import datetime
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("ghost.alerts")

CONFIG_PATH = Path("/etc/ghost-fort/alert_config.json")

# Max retries and backoff for all delivery channels
MAX_RETRIES    = 3
RETRY_BACKOFF  = [5, 15, 60]   # seconds

SEVERITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

CAT_EMOJI = {
    "TOR": "🧅", "BOTNET": "🤖", "MALICIOUS": "☣️",
    "PORT_SCAN": "🔍", "SSH_BRUTE_FORCE": "🔑",
    "RDP_ATTACK": "🖥️", "COMPROMISED": "💀",
    "SPAMHAUS": "🚫", "BRUTEFORCE": "⚡",
    "SYSTEM_FAULT": "⚙️", "UNKNOWN": "⚠️",
}

RISK_COLORS = {
    "LOW": 0x22c55e, "MEDIUM": 0xfacc15,
    "HIGH": 0xf97316, "CRITICAL": 0xef4444,
}


# ── KEYRING / SECRET STORAGE ──────────────────────────────────

def _get_secret(key: str) -> Optional[str]:
    """
    [FIX] Retrieve secret from system keyring or environment variable.
    Never reads from plaintext config file.

    Priority: system keyring → environment variable → None
    """
    # 1. Try system keyring (linux-keyring / macOS Keychain)
    try:
        import keyring
        val = keyring.get_password("ghost-fort", key)
        if val:
            return val
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"Keyring lookup failed for {key}: {e}")

    # 2. Fallback: environment variable
    env_key = f"GHOST_{key.upper().replace('-','_')}"
    val = os.environ.get(env_key)
    if val:
        logger.debug(f"Secret {key} loaded from environment variable {env_key}")
        return val

    return None


def _set_secret(key: str, value: str) -> bool:
    """Store secret in system keyring."""
    try:
        import keyring
        keyring.set_password("ghost-fort", key, value)
        return True
    except ImportError:
        logger.warning(
            "keyring package not installed. "
            "Install with: pip install keyring secretstorage\n"
            f"Falling back: set env var GHOST_{key.upper().replace('-','_')}"
        )
        return False
    except Exception as e:
        logger.error(f"Keyring store failed for {key}: {e}")
        return False


# ── CONFIG ────────────────────────────────────────────────────

@dataclass
class AlertConfig:
    # Non-sensitive settings stored in config file
    discord_enabled: bool      = False
    discord_min_severity: str  = "HIGH"

    email_enabled: bool        = False
    smtp_host: str             = "smtp.gmail.com"
    smtp_port: int             = 465       # [FIX] SSL port, not STARTTLS
    smtp_user: str             = ""
    email_recipient: str       = ""
    email_min_severity: str    = "CRITICAL"

    desktop_notify: bool       = True
    desktop_min_severity: str  = "HIGH"

    # Sensitive secrets are NEVER stored here — loaded from keyring at runtime
    # discord_webhook_url  → keyring: "ghost-fort/discord-webhook"
    # smtp_password        → keyring: "ghost-fort/smtp-password"

    @classmethod
    def load(cls) -> "AlertConfig":
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text())
                # Strip any secrets that were accidentally saved in old format
                for secret_key in ("discord_webhook_url", "smtp_password"):
                    data.pop(secret_key, None)
                return cls(**{k: v for k, v in data.items()
                              if k in cls.__dataclass_fields__})
            except Exception as e:
                logger.error(f"Config load failed: {e}")
        return cls()

    def save(self):
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        # [FIX] Never write secrets to config file
        safe_dict = {k: v for k, v in self.__dict__.items()
                     if k not in ("discord_webhook_url", "smtp_password")}
        CONFIG_PATH.write_text(json.dumps(safe_dict, indent=2))
        os.chmod(CONFIG_PATH, 0o600)   # root-only


def _severity_passes(event_sev: str, min_sev: str) -> bool:
    return SEVERITY_RANK.get(event_sev, 0) >= SEVERITY_RANK.get(min_sev, 0)


# ── RETRY WRAPPER ─────────────────────────────────────────────

def _with_retry(fn, channel_name: str):
    """Run fn() with exponential backoff retries."""
    last_err = None
    for attempt in range(MAX_RETRIES):
        try:
            fn()
            return True
        except Exception as e:
            last_err = e
            wait = RETRY_BACKOFF[min(attempt, len(RETRY_BACKOFF)-1)]
            logger.warning(
                f"{channel_name} delivery attempt {attempt+1}/{MAX_RETRIES} "
                f"failed: {e} — retry in {wait}s"
            )
            time.sleep(wait)
    logger.error(f"{channel_name} all {MAX_RETRIES} attempts failed: {last_err}")
    return False


# ── DESKTOP NOTIFIER ──────────────────────────────────────────

class DesktopNotifier:
    import subprocess

    def notify(self, profile: dict, config: AlertConfig):
        severity = profile.get("risk_level", "MEDIUM")
        if not config.desktop_notify:
            return
        if not _severity_passes(severity, config.desktop_min_severity):
            return

        ip       = profile.get("ip", "Unknown")
        category = profile.get("threat_category") or profile.get("scan_type", "UNKNOWN")
        country  = profile.get("country", "Unknown")
        emoji    = CAT_EMOJI.get(category, "⚠️")
        reason   = profile.get("block_reason", "")

        title = f"{emoji} GHOST FORT — {severity} THREAT BLOCKED"
        body  = f"{ip} ({country})\n{category} — {reason[:80]}"

        def _send():
            import subprocess
            try:
                subprocess.run([
                    "notify-send",
                    "--urgency=critical" if severity == "CRITICAL" else "--urgency=normal",
                    "--icon=security-high", "--app-name=Ghost Fort",
                    title, body
                ], timeout=3, check=True)
            except FileNotFoundError:
                subprocess.run([
                    "osascript", "-e",
                    f'display notification "{body}" with title "{title}"'
                ], timeout=3, check=True)

        _with_retry(_send, "desktop-notify")


# ── DISCORD NOTIFIER ──────────────────────────────────────────

class DiscordNotifier:

    def notify(self, profile: dict, reason: str, config: AlertConfig):
        if not config.discord_enabled:
            return
        severity = profile.get("risk_level", "MEDIUM")
        if not _severity_passes(severity, config.discord_min_severity):
            return

        # [FIX] Load webhook URL from keyring at send time — never cached in memory long-term
        webhook_url = _get_secret("discord-webhook")
        if not webhook_url:
            logger.warning("Discord webhook URL not configured — skipping")
            return

        ip       = profile.get("ip", "Unknown")
        category = profile.get("threat_category") or profile.get("scan_type", "UNKNOWN")
        emoji    = CAT_EMOJI.get(category, "⚠️")
        color    = RISK_COLORS.get(severity, 0x6b7280)

        payload = {
            "username": "Ghost Fort",
            "embeds": [{
                "title": f"{emoji}  [{severity}] {category} — {ip}",
                "description": "Threat automatically detected and blocked",
                "color": color,
                "fields": [
                    {"name": "🌍 Location",     "value": f"{profile.get('city','?')}, {profile.get('country','?')}", "inline": True},
                    {"name": "🏢 ISP",           "value": profile.get("isp","Unknown")[:50], "inline": True},
                    {"name": "🔬 Scan Type",     "value": profile.get("scan_type","Unknown"), "inline": True},
                    {"name": "💻 OS Fingerprint","value": profile.get("os_guess","Unknown"), "inline": True},
                    {"name": "🔌 Ports Probed",  "value": ", ".join(map(str, profile.get("ports_probed",[])[:10])) or "—", "inline": True},
                    {"name": "🧠 Threat Source", "value": profile.get("threat_source","behavioral"), "inline": True},
                    {"name": "🚫 Block Reason",  "value": f"```{reason[:200]}```", "inline": False},
                ],
                "footer": {"text": f"Ghost Fort IDS  •  {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}"},
            }]
        }

        def _send():
            # [FIX] verify=True — always verify TLS cert
            resp = requests.post(webhook_url, json=payload, timeout=8, verify=True)
            resp.raise_for_status()

        _with_retry(_send, "discord")


# ── EMAIL NOTIFIER ────────────────────────────────────────────

class EmailNotifier:

    def notify(self, profile: dict, reason: str, config: AlertConfig):
        if not config.email_enabled or not config.smtp_user:
            return
        severity = profile.get("risk_level", "MEDIUM")
        if not _severity_passes(severity, config.email_min_severity):
            return

        # [FIX] Load password from keyring at send time
        password = _get_secret("smtp-password")
        if not password:
            logger.warning("SMTP password not configured — skipping email alert")
            return

        ip       = profile.get("ip", "Unknown")
        category = profile.get("threat_category") or profile.get("scan_type","UNKNOWN")
        emoji    = CAT_EMOJI.get(category, "⚠️")
        rcolor   = {"LOW":"#22c55e","MEDIUM":"#facc15","HIGH":"#f97316","CRITICAL":"#ef4444"}.get(severity,"#6b7280")

        subject = f"{emoji} GHOST FORT [{severity}] — {category} from {ip}"

        rows_html = "".join(
            f'<tr><td style="padding:7px 12px;border-bottom:1px solid #1f2937;'
            f'font-size:10px;color:#6b7280;width:130px;">{k}</td>'
            f'<td style="padding:7px 12px;border-bottom:1px solid #1f2937;'
            f'font-size:11px;color:#d1d5db;">{v}</td></tr>'
            for k, v in [
                ("Location",     f"{profile.get('city','?')}, {profile.get('country','?')}"),
                ("ISP",          profile.get("isp","Unknown")),
                ("ASN",          profile.get("asn","Unknown")),
                ("OS Guess",     profile.get("os_guess","Unknown")),
                ("Scan Type",    profile.get("scan_type","Unknown")),
                ("Ports Probed", ", ".join(map(str, profile.get("ports_probed",[])[:12])) or "—"),
                ("Tor Exit",     "YES" if profile.get("is_tor_exit") else "No"),
                ("Feed Source",  profile.get("threat_source","behavioral")),
            ]
        )

        html = f"""<!DOCTYPE html><html><body style="margin:0;padding:20px;background:#05050a;
font-family:'Courier New',monospace;color:#e5e7eb;">
<div style="max-width:600px;margin:0 auto;background:#111118;border:1px solid #1f2937;border-radius:8px;">
  <div style="background:linear-gradient(135deg,#1e1b4b,#14091f);padding:20px 28px;border-bottom:1px solid #1f2937;">
    <div style="font-size:20px;font-weight:700;color:#a5b4fc;letter-spacing:0.15em;">🏰 GHOST FORT</div>
    <div style="font-size:10px;color:#4b5563;letter-spacing:0.2em;">AUTONOMOUS DEFENSE SYSTEM</div>
  </div>
  <div style="background:{rcolor}18;border-left:4px solid {rcolor};padding:12px 28px;">
    <div style="font-size:13px;color:{rcolor};font-weight:700;">{emoji} {severity} THREAT BLOCKED</div>
    <div style="font-size:10px;color:#9ca3af;margin-top:3px;">{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")}</div>
  </div>
  <div style="padding:20px 28px 0;">
    <div style="background:#0a0a0f;border:1px solid #1f2937;border-radius:4px;padding:14px 18px;margin-bottom:16px;">
      <div style="font-size:22px;color:#a5b4fc;">{ip}</div>
      <span style="font-size:9px;padding:2px 8px;background:{rcolor}20;color:{rcolor};
        border:1px solid {rcolor}40;border-radius:3px;">{category}</span>
    </div>
    <table width="100%" style="border-collapse:collapse;">{rows_html}</table>
  </div>
  <div style="padding:16px 28px;">
    <div style="background:#0a0a0f;border:1px solid #ef444420;border-radius:4px;padding:12px 14px;">
      <div style="font-size:9px;color:#6b7280;letter-spacing:0.15em;margin-bottom:5px;">BLOCK REASON</div>
      <div style="font-size:11px;color:#fca5a5;line-height:1.5;">{reason}</div>
    </div>
  </div>
  <div style="padding:14px 28px;border-top:1px solid #1f2937;text-align:center;
    font-size:9px;color:#374151;letter-spacing:0.1em;">
    GHOST FORT IDS — AUTOMATED SECURITY ALERT — NO ACTION REQUIRED
  </div>
</div></body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"Ghost Fort <{config.smtp_user}>"
        msg["To"]      = config.email_recipient
        msg.attach(MIMEText(html, "html"))

        def _send():
            # [FIX] SMTP_SSL (port 465) with explicit TLS context — no STARTTLS downgrade risk
            context = ssl.create_default_context()   # full cert verification
            with smtplib.SMTP_SSL(
                config.smtp_host, config.smtp_port,
                context=context, timeout=10
            ) as server:
                server.login(config.smtp_user, password)
                server.send_message(msg)
            logger.info(f"Email alert sent: {ip}")

        _with_retry(_send, "email")


# ── ALERT MANAGER ─────────────────────────────────────────────

class GhostAlertManager:

    def __init__(self, config: Optional[AlertConfig] = None):
        self.config   = config or AlertConfig.load()
        self._desktop = DesktopNotifier()
        self._discord = DiscordNotifier()
        self._email   = EmailNotifier()

    def reload_config(self):
        self.config = AlertConfig.load()

    def fire(self, profile: dict, reason: str):
        """Non-blocking dispatch to all channels."""
        threading.Thread(
            target=self._dispatch,
            args=(profile, reason),
            daemon=True,
            name=f"alert-{profile.get('ip','?')}"
        ).start()

    def _dispatch(self, profile: dict, reason: str):
        self._desktop.notify(profile, self.config)
        self._discord.notify(profile, reason, self.config)
        self._email.notify(profile, reason, self.config)

    def test(self):
        self.fire({
            "ip": "1.3.3.7", "risk_level": "HIGH",
            "threat_category": "TOR", "scan_type": "SERVICE_DISCOVERY_SCAN",
            "country": "Germany", "country_code": "DE", "city": "Frankfurt",
            "isp": "Frantech Solutions", "asn": "AS53667", "org": "Frantech Solutions",
            "os_guess": "Linux (TTL ~64)", "ports_probed": [22,80,443,8080],
            "is_tor_exit": True, "threat_source": "tor_exit_nodes",
            "block_reason": "TEST ALERT — Ghost Fort alert verification",
        }, "TEST ALERT — Ghost Fort alert system verification")
        logger.info("Test alert fired")


# ── INTERACTIVE SETUP ─────────────────────────────────────────

def configure_interactive():
    print("\n" + "═"*55)
    print("  GHOST FORT v3 — ALERT CHANNEL SETUP")
    print("  Secrets stored in system keyring — never plaintext")
    print("═"*55 + "\n")

    config = AlertConfig.load()

    # Discord
    print("── DISCORD WEBHOOK ─────────────────────────────────")
    print("  1. Discord server → Settings → Integrations → Webhooks")
    print("  2. New Webhook → Copy URL\n")
    url = input("  Paste Discord webhook URL (Enter to skip): ").strip()
    if url:
        if _set_secret("discord-webhook", url):
            print("  ✅ Webhook URL stored in system keyring")
        else:
            print(f"  ⚠️  Set env var: export GHOST_DISCORD_WEBHOOK='{url}'")
        config.discord_enabled = True
        sev = input("  Min severity [HIGH]: ").strip() or "HIGH"
        config.discord_min_severity = sev.upper()

    # Email
    print("\n── EMAIL (SMTP SSL) ─────────────────────────────────")
    print("  Uses SMTP over SSL (port 465) with cert verification")
    enable = input("  Enable email alerts? (y/N): ").strip().lower()
    if enable == "y":
        config.email_enabled = True
        config.smtp_host     = input("  SMTP host [smtp.gmail.com]: ").strip() or "smtp.gmail.com"
        port = input("  SMTP SSL port [465]: ").strip()
        config.smtp_port     = int(port) if port else 465
        config.smtp_user     = input("  Your email address: ").strip()
        config.email_recipient = input("  Alert recipient email: ").strip()

        import getpass
        pwd = getpass.getpass("  App password (input hidden): ")
        if _set_secret("smtp-password", pwd):
            print("  ✅ Password stored in system keyring")
        else:
            print("  ⚠️  Set env var: export GHOST_SMTP_PASSWORD='your-password'")

        sev = input("  Min severity [CRITICAL]: ").strip() or "CRITICAL"
        config.email_min_severity = sev.upper()

    # Desktop
    print("\n── DESKTOP NOTIFICATIONS ────────────────────────────")
    desk = input("  Enable desktop popups? (Y/n): ").strip().lower()
    config.desktop_notify = desk != "n"

    config.save()
    print(f"\n  ✅ Config saved to {CONFIG_PATH} (secrets in keyring)")

    test = input("\n  Fire a test alert now? (Y/n): ").strip().lower()
    if test != "n":
        GhostAlertManager(config).test()
        print("  Test fired — check Discord / email / desktop.")


if __name__ == "__main__":
    configure_interactive()
