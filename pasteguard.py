#!/usr/bin/env python3

import argparse, base64, hashlib, json, os, re, subprocess, tempfile
import threading, time, tkinter as tk, unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import numpy as np
import requests
import pyperclip
from pynput import keyboard


# TensorFlow (optional – CNN model)
try:
    import tensorflow as tf
    HAS_TF = True
except ImportError:
    tf = None
    HAS_TF = False

# Optional plyer notifications

try:
    from plyer import notification as plyer_notification
except ImportError:
    plyer_notification = None


# CONFIGURATION – set your keys here or leave empty to disable

VIRUSTOTAL_API_KEY = ""          # free from virustotal.com
SLACK_WEBHOOK_URL  = ""       # e.g. https://hooks.slack.com/services/...
COMMAND_CLASSIFIER_PKL = r"your command_classifier.pkl file path here"

# CNN model path and character mappingmust match training

CNN_MODEL_PATH = r"C:\TURBOC3\BIN\PROJECT\pasteguard\clipboard\command_classifier_cnn.h5"

CHARS = " -'!%&()*,./:;?@[\\]_`{|}+<=>û#$^˜\""
CHAR_TO_IDX = {c: i for i, c in enumerate(CHARS)}
MAX_LEN = 1024

def encode_command(cmd: str):
    """Convert a command to a (len(CHARS)+1) × MAX_LEN matrix."""
    matrix = np.zeros((len(CHARS) + 1, MAX_LEN), dtype='float32')
    for i, ch in enumerate(cmd[:MAX_LEN]):
        lower_ch = ch.lower()
        if lower_ch in CHAR_TO_IDX:
            idx = CHAR_TO_IDX[lower_ch]
            matrix[idx, i] = 1.0               # character one-hot
            if ch.isupper():
                matrix[-1, i] = 1.0            # case bit (last row)
    return matrix

# CNN model loader

_cnn_model = None
def _load_cnn_model():
    global _cnn_model
    if _cnn_model is not None:
        return _cnn_model
    if not os.path.exists(CNN_MODEL_PATH) or not HAS_TF:
        return None
    _cnn_model = tf.keras.models.load_model(CNN_MODEL_PATH)
    return _cnn_model

def cnn_predict(text: str) -> Optional[bool]:
    model = _load_cnn_model()
    if model is None:
        return None
    try:
        matrix = encode_command(text)
        matrix = matrix.reshape(1, len(CHARS) + 1, MAX_LEN, 1)
        score = model.predict(matrix, verbose=0)[0][0]
        return score > 0.5
    except Exception:
        return None

# Logistic regression AI model (fallback)


_ai_model = None
def _load_ai_model():
    global _ai_model
    if _ai_model is not None:
        return _ai_model
    if not os.path.exists(COMMAND_CLASSIFIER_PKL):
        return None
    try:
        import joblib
        _ai_model = joblib.load(COMMAND_CLASSIFIER_PKL)
        return _ai_model
    except Exception:
        return None

def ai_predict(text: str) -> Optional[bool]:
    model = _load_ai_model()
    if model is None:
        return None
    try:
        return bool(model.predict([text])[0])
    except Exception:
        return None

# VirusTotal full URL check (base64‑encoded)

def check_url_virustotal(full_url: str) -> Tuple[int, str]:
    if not VIRUSTOTAL_API_KEY:
        return 0, "no key"
    try:
        encoded = base64.urlsafe_b64encode(full_url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{encoded}",
                            headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            score = malicious * 10 + suspicious * 5
            details = f"VT URL: {malicious}/{harmless+malicious+suspicious} malicious"
            return min(90, score), details
        elif resp.status_code == 404:
            return 0, "VT URL: not scanned yet"
        else:
            return 0, f"VT URL error {resp.status_code}"
    except Exception as e:
        return 0, f"VT URL error: {e}"

def check_domain_virustotal(domain: str) -> Tuple[int, str]:
    if not VIRUSTOTAL_API_KEY:
        return 0, "no key"
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                            headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            score = malicious * 10 + suspicious * 5
            details = f"VT domain: {malicious}/{harmless+malicious+suspicious} malicious"
            return min(90, score), details
        else:
            return 0, f"VT domain error {resp.status_code}"
    except Exception as e:
        return 0, f"VT domain error: {e}"

def check_domain_urlhaus(domain: str) -> Tuple[int, str]:
    try:
        headers = {"User-Agent": "PasteGuard/2.0"}
        resp = requests.post("https://urlhaus-api.abuse.ch/v1/host/",
                             data={"host": domain}, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "ok" and data.get("url_count", 0) > 0:
                return 70, "URLhaus: known malicious host"
            return 0, "URLhaus: clean"
        return 0, f"URLhaus error {resp.status_code}"
    except Exception as e:
        return 0, f"URLhaus error: {e}"

def check_domain_whois_age(domain: str) -> Tuple[int, str]:
    try:
        import whois
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            now = datetime.now(timezone.utc)
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (now - creation_date).days
            if age_days < 7:
                return 60, f"WHOIS: {age_days}d old (very new)"
            else:
                return 0, f"WHOIS: {age_days}d old"
        return 0, "WHOIS: no creation date"
    except Exception:
        return 0, "WHOIS: domain not found"

def check_full_url_reputation(full_url: str) -> Tuple[int, str]:
    url_risk, url_detail = check_url_virustotal(full_url)
    parsed = urlparse(full_url)
    domain_risk, domain_detail = 0, ""
    if parsed.hostname:
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed.hostname):
            domain_risk, domain_detail = check_domain_virustotal(parsed.hostname)
        else:
            vt_domain, vt_detail = check_domain_virustotal(parsed.hostname)
            uh_risk, uh_detail = check_domain_urlhaus(parsed.hostname)
            w_risk, w_detail = check_domain_whois_age(parsed.hostname)
            domain_risk = max(vt_domain, uh_risk, w_risk)
            domain_detail = f"VT domain: {vt_detail}\n{uh_detail}\n{w_detail}"
    combined_risk = max(url_risk, domain_risk)
    combined_detail = f"URL: {url_detail}\nDomain: {domain_detail}"
    return min(100, combined_risk), combined_detail

# Sandbox (Docker required)

def sandbox_analysis(command: str) -> List[str]:
    obs = []
    try:
        subprocess.run(["docker", "version"], capture_output=True, check=True, timeout=5)
    except Exception:
        return obs
    with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
        f.write("#!/bin/sh\n" + command + "\n")
        script_path = f.name
    os.chmod(script_path, 0o755)
    try:
        cmd = [
            "docker", "run", "--rm", "--network", "none",
            "-v", f"{script_path}:/tmp/cmd.sh:ro",
            "alpine:latest", "sh", "-c",
            "apk add --no-cache strace >/dev/null 2>&1; strace -f -e trace=file,network sh /tmp/cmd.sh 2>&1"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        if "connect(" in output:
            obs.append("Network connection attempted (blocked)")
        if "open(" in output and "WRONLY" in output:
            obs.append("File write operation detected")
        if "execve(" in output and ("bash" in output or "sh" in output):
            obs.append("Sub‑shell spawn detected")
    except Exception as e:
        print(f"[SANDBOX] Error: {e}")
    finally:
        os.unlink(script_path)
    return obs

# Evasion helpers

def check_polymorphic_patterns(text: str) -> Optional[str]:
    for pat, desc in [
        (r'\b(c)(\"{2}|``)\s*url\b', "Polymorphic curl"),
        (r'\b(w)(\"{2}|``)\s*get\b', "Polymorphic wget"),
        (r'\bb\$\{[a-z]+\}sh\b', "Polymorphic bash"),
    ]:
        if re.search(pat, text, re.IGNORECASE):
            return desc
    return None

def check_whitespace_steganography(text: str) -> Optional[str]:
    for line in text.splitlines():
        if re.search(r'[a-zA-Z0-9]\s{2,}[a-zA-Z0-9]', line):
            return "Unusual whitespace pattern (possible steganography)"
    return None

# Data structures

@dataclass
class Issue:
    code: str
    message: str
    severity: int

@dataclass
class AnalysisResult:
    looks_like_command: bool
    danger_score: int
    danger_level: str
    issues: List[Issue] = field(default_factory=list)
    preview: str = ""
    sanitized_text: str = ""
    domains: List[str] = field(default_factory=list)

# Main analyser

class CommandAnalyzer:
    COMMAND_PREFIXES = {
        "sudo", "apt", "apt-get", "dnf", "yum", "pacman", "brew",
        "pip", "pip3", "python", "python3", "npm", "pnpm", "yarn", "npx",
        "node", "git", "curl", "wget", "bash", "sh", "zsh", "pwsh",
        "powershell", "cmd", "reg", "scp", "ssh", "kubectl", "docker",
        "rm", "mkfs", "dd", "chmod", "chown", "echo", "export",
        "setx", "net", "schtasks", "crontab", "systemctl", "launchctl",
        "mshta", "rundll32", "regsvr32", "set", "for", "certutil", "bitsadmin"
    }
    INVISIBLE_CHARS = {
        "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
        "\u2066", "\u2067", "\u2068", "\u2069",
    }
    HOMOGLYPH_OPERATORS = {
        "\uff06": "&", "\u2223": "|", "\uff5c": "|", "\uff1b": ";",
        "\u2044": "/", "\uff0d": "-",
    }
    SHELL_SEPARATORS = re.compile(r"(;|\|\||&&|\||`|\$\(|\n)")
    MALICIOUS_PATTERNS = [
        (re.compile(r"(curl|wget)[^\n]{0,200}\|\s*(bash|sh|zsh|pwsh|powershell|cmd)", re.I),
         "Pipes downloaded content directly to a shell.", 80),
        (re.compile(r"(curl|wget|certutil|bitsadmin)\s+.+&&\s*(start\s|bash|sh|cmd|powershell)", re.I),
         "Downloads a file and immediately executes it.", 85),
        (re.compile(r"(curl|wget|certutil|bitsadmin).+%TEMP%.+&.+start\s+%TEMP%", re.I),
         "Downloads to TEMP and attempts execution.", 85),
        (re.compile(r"bash\s+-i\s*>&\s*/dev/tcp/", re.I), "Interactive reverse shell.", 90),
        (re.compile(r"nc\s+(-e|-c)\s+/bin/(bash|sh)", re.I), "Netcat reverse shell.", 85),
        (re.compile(r"reg\s+add\s+.*\\Run\b", re.I), "Windows Run registry persistence.", 85),
        (re.compile(r"schtasks\s+/create.*(/sc\s+(hourly|daily|onlogon|onstart))", re.I), "Scheduled task persistence.", 80),
        (re.compile(r"rm\s+-rf\s+/", re.I), "Recursive force delete of root.", 100),
        (re.compile(r"mkfs\.\w+\s+/dev/sd[a-z]", re.I), "Filesystem format command.", 95),
        (re.compile(r"dd\s+if=/dev/zero\s+of=/dev/sd[a-z]", re.I), "Disk wiping with zeroes.", 100),
        (re.compile(r"for\s+%[a-z]\s+in\s*\(.*(curl|wget|cmd|powershell)", re.I), "Obfuscated execution via 'for' loop.", 75),
        (re.compile(r"certutil\s+-urlcache\s+-split\s+-f\s+http", re.I), "Downloads file via certutil.", 80),
        (re.compile(r"bitsadmin\s+/transfer\s+.+http", re.I), "Downloads file via BITSAdmin.", 80),
        (re.compile(r"mshta\s+http", re.I), "Downloads and executes an HTA file.", 85),
        (re.compile(r"rundll32\s+.*javascript:", re.I), "Uses rundll32 to execute script.", 85),
        (re.compile(r"regsvr32\s+/s\s+/n\s+/u\s+/i:http", re.I), "Downloads COM scriptlet via regsvr32.", 90),
        (re.compile(r"echo\s+\S+\s*\|\s*base64\s+-d\s*\|", re.I), "Base64 decoded payload piped.", 85),
        (re.compile(r"powershell.*-(enc|encodedcommand)\s+\S+", re.I), "Encoded PowerShell command.", 80),
        (re.compile(r"echo\s+.*>>\s*~/.bashrc", re.I), "Appending to .bashrc.", 80),
        (re.compile(r"echo\s+.*\|\s*crontab\s*-", re.I), "Piping to crontab.", 85),
        (re.compile(r"chmod\s+u\+s\s+/bin/(bash|sh)", re.I), "SUID shell.", 90),
    ]

    def looks_like_command(self, text: str) -> bool:
        stripped = text.strip()
        if not stripped:
            return False
        first = stripped.split()[0].lower()
        if first in self.COMMAND_PREFIXES:
            return True
        if self.SHELL_SEPARATORS.search(stripped):
            return True
        return False

    def analyze(self, text: str) -> AnalysisResult:
        issues: List[Issue] = []
        self._check_hidden_chars(text, issues)
        poly = check_polymorphic_patterns(text)
        if poly:
            issues.append(Issue("polymorphic", poly, 70))
        ws = check_whitespace_steganography(text)
        if ws:
            issues.append(Issue("whitespace", ws, 60))
        for pat, desc, sev in self.MALICIOUS_PATTERNS:
            if pat.search(text):
                issues.append(Issue("malicious_pattern", desc, sev))
        for m in re.finditer(r"https?://[^\s'\"<>]+", text):
            full_url = m.group(0)
            risk, details = check_full_url_reputation(full_url)
            print(f"[REPUTATION] {full_url} → risk={risk}\n{details}")
            if risk >= 20:
                issues.append(Issue("url_reputation", f"URL '{full_url}' risk {risk}/100:\n{details}", risk))
        score = sum(i.severity for i in issues)
        level = "SAFE"
        if score >= 80:
            level = "DANGEROUS"
        elif score >= 45:
            level = "SUSPICIOUS"
        elif score >= 20:
            level = "CAUTION"
        sanitized = self._sanitize(text)
        preview = re.sub(r"\s+", " ", text).strip()
        if len(preview) > 120:
            preview = preview[:117] + "..."
        return AnalysisResult(
            looks_like_command=self.looks_like_command(text),
            danger_score=score,
            danger_level=level,
            issues=issues,
            preview=preview,
            sanitized_text=sanitized,
            domains=[urlparse(u).hostname for u in re.findall(r"https?://[^\s'\"<>]+", text) if urlparse(u).hostname],
        )

    def _check_hidden_chars(self, text: str, issues: List[Issue]) -> None:
        hidden, homoglyphs = [], []
        for ch in text:
            if ch in self.INVISIBLE_CHARS or unicodedata.category(ch) == "Cf":
                hidden.append(f"U+{ord(ch):04X}")
            if ch in self.HOMOGLYPH_OPERATORS:
                homoglyphs.append(f"U+{ord(ch):04X} ({self.HOMOGLYPH_OPERATORS[ch]})")
        if hidden:
            issues.append(Issue("hidden_chars", f"Hidden Unicode: {', '.join(set(hidden)[:6])}", 90))
        if homoglyphs:
            issues.append(Issue("homoglyph", f"Look‑alike operators: {', '.join(set(homoglyphs)[:6])}", 70))

    def _sanitize(self, text: str) -> str:
        clean = []
        for ch in text:
            cat = unicodedata.category(ch)
            if ch in self.INVISIBLE_CHARS:
                continue
            if cat == "Cc" and ch not in ("\t", "\n", "\r"):
                continue
            clean.append(ch)
        cleaned = "".join(clean)
        cleaned = cleaned.replace("\r", " ").replace("\n", " ").replace("\t", " ")
        return re.sub(r"\s+", " ", cleaned).strip()


# Notification & Slack

class Notifier:
    @staticmethod
    def show(title: str, msg: str):
        if plyer_notification:
            try:
                plyer_notification.notify(title=title, message=msg[:256], app_name="PasteGuard", timeout=10)
            except Exception:
                pass
        print(f"[NOTIFY] {title}: {msg}")

def log_and_slack(result: AnalysisResult, original: str):
    entry = {
        "timestamp": datetime.now().isoformat(),
        "danger_level": result.danger_level,
        "score": result.danger_score,
        "preview": result.preview,
        "issues": [{"code": i.code, "message": i.message, "severity": i.severity} for i in result.issues],
    }
    with open("pasteguard_alerts.json", "a") as f:
        f.write(json.dumps(entry) + "\n")
    if SLACK_WEBHOOK_URL:
        issue_lines = "\n".join(f"• {i.message}" for i in result.issues[:5])
        text = f"*PasteGuard {result.danger_level}*\n`{result.preview}`\n{issue_lines}\nScore: {result.danger_score}"
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": text}, timeout=5)
        except Exception as e:
            print(f"[SLACK] Error: {e}")

# Clipboard watcher

class ClipboardWatcher:
    def __init__(self, poll_interval=0.5, on_stop=None):
        self.interval = poll_interval
        self._running = False
        self._last_hash = None
        self._on_change_callback = None
        self._on_stop = on_stop
        self._listener = None

    def run(self, callback: Callable[[str], None]):
        self._on_change_callback = callback
        self._running = True
        threading.Thread(target=self._poll_loop, daemon=True).start()
        self._start_keyboard_listener()

    def _poll_loop(self):
        while self._running:
            text = self._safe_paste()
            if text:
                h = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
                if h != self._last_hash:
                    self._last_hash = h
                    self._on_change_callback(text)
            time.sleep(self.interval)

    def _start_keyboard_listener(self):
        def on_activate():
            text = self._safe_paste()
            if text:
                h = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
                if h != self._last_hash:
                    self._last_hash = h
                    self._on_change_callback(text)

        def quit_guard():
            print("Shutdown hotkey pressed.")
            self._running = False
            if self._listener:
                self._listener.stop()
            if self._on_stop:
                self._on_stop()

        try:
            self._listener = keyboard.GlobalHotKeys({
                '<ctrl>+c': on_activate,
                '<ctrl>+<alt>+<shift>+q': quit_guard
            })
            self._listener.start()
        except Exception as e:
            print(f"[KEYBOARD] Could not start listener: {e}")

    def stop(self):
        self._running = False
        if self._listener:
            try:
                self._listener.stop()
            except Exception:
                pass

    @staticmethod
    def _safe_paste() -> Optional[str]:
        try:
            return pyperclip.paste()
        except Exception:
            return None


# Main app

class PasteGuardApp:
    def __init__(self, poll=0.5):
        self.analyzer = CommandAnalyzer()
        self.watcher = ClipboardWatcher(poll, on_stop=self.shutdown)
        self.root = tk.Tk()
        self.root.withdraw()
        self._stop_event = threading.Event()

    def start(self):
        print("PasteGuard ULTIMATE v2.0 – Ctrl+C/right‑click copy works, Ctrl+Alt+Shift+Q to stop.")
        self.watcher.run(self._on_copy)
        try:
            self.root.mainloop()
        finally:
            self.shutdown()

    def shutdown(self):
        if self._stop_event.is_set():
            return
        self._stop_event.set()
        self.watcher.stop()
        try:
            self.root.quit()
            self.root.destroy()
        except Exception:
            pass
        print("PasteGuard fully stopped.")

    def _on_copy(self, text: str):
        if not text or not text.strip():
            return
        try:
            result = self.analyzer.analyze(text)
        except Exception as e:
            print(f"[ERROR] analysis: {e}")
            return

        # Debug output
        print(f"\n[DEBUG] Preview: {result.preview[:80]}")
        print(f"[DEBUG] Looks like command: {result.looks_like_command}")
        print(f"[DEBUG] Score: {result.danger_score}, Level: {result.danger_level}")
        if result.issues:
            for issue in result.issues:
                print(f"  - Issue: {issue.message} (sev {issue.severity})")
        else:
            print("  - No issues found")

        if not result.looks_like_command:
            return

        # AI ensemble for mild scores
        if 0 < result.danger_score < 45:
            old_ai = ai_predict(text)
            cnn_ai = cnn_predict(text)
            if old_ai or cnn_ai:
                print(f"[AI] old={old_ai}, CNN={cnn_ai} – escalating")
                result.issues.append(Issue("ai_flag", "AI classifier flagged as suspicious.", 40))
                result.danger_score += 40
                if result.danger_score >= 80:
                    result.danger_level = "DANGEROUS"
                elif result.danger_score >= 45:
                    result.danger_level = "SUSPICIOUS"

        # Sandbox for high risk
        if result.danger_level in ("DANGEROUS", "SUSPICIOUS"):
            obs = sandbox_analysis(result.sanitized_text)
            for o in obs:
                result.issues.append(Issue("sandbox", o, 30))
                result.danger_score += 30

        # Recalculate final level
        if result.danger_score >= 80:
            result.danger_level = "DANGEROUS"
        elif result.danger_score >= 45:
            result.danger_level = "SUSPICIOUS"
        elif result.danger_score >= 20:
            result.danger_level = "CAUTION"

        if result.danger_level in ("DANGEROUS", "SUSPICIOUS", "CAUTION"):
            summary = "; ".join(i.message for i in result.issues[:2])
            Notifier.show(f"PasteGuard {result.danger_level}", summary)
            print(f"⚠️ {result.danger_level} (score {result.danger_score}): {result.preview}")
            for issue in result.issues:
                print(f"  - {issue.message}")
            log_and_slack(result, text)

# Entry point

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--poll", type=float, default=0.5)
    args = parser.parse_args()
    app = PasteGuardApp(poll=args.poll)
    try:
        app.start()
    except KeyboardInterrupt:
        app.shutdown()
        print("PasteGuard stopped.")

if __name__ == "__main__":
    main()