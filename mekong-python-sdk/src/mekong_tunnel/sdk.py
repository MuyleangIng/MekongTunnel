"""
mekong_tunnel.sdk — Programmatic Python API for MekongTunnel.

Usage::

    import mekong_tunnel as mekong

    # Expose a local port (blocking until tunnel URL is received)
    tunnel = mekong.expose(8000)
    print("Public URL:", tunnel.url)
    # …later…
    tunnel.stop()

    # Auth helpers
    token = mekong.get_token()
    mekong.login()   # opens browser, waits for approval, saves ~/.mekong/config.json
    mekong.logout()  # removes saved credentials
    info = mekong.whoami()
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import webbrowser
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

API_BASE = "https://api.angkorsearch.dev"
WEB_BASE = "https://angkorsearch.dev"

# ── Config helpers ────────────────────────────────────────────────────────────

def _mekong_dir() -> Path:
    return Path.home() / ".mekong"


def _config_path() -> Path:
    return _mekong_dir() / "config.json"


def get_token() -> Optional[str]:
    """Return the API token from env var or saved login, or None."""
    if tok := os.environ.get("MEKONG_TOKEN", "").strip():
        return tok
    try:
        cfg = json.loads(_config_path().read_text())
        return cfg.get("token") or None
    except Exception:
        return None


def _load_config() -> Optional[dict]:
    try:
        return json.loads(_config_path().read_text())
    except Exception:
        return None


def _save_config(cfg: dict) -> None:
    _mekong_dir().mkdir(parents=True, exist_ok=True)
    p = _config_path()
    p.write_text(json.dumps(cfg, indent=2))
    p.chmod(0o600)


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _api_post(path: str) -> dict:
    url = API_BASE + path
    req = urllib.request.Request(url, data=b"", method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _api_get(path: str) -> dict:
    with urllib.request.urlopen(API_BASE + path, timeout=15) as resp:
        return json.loads(resp.read())


def _unwrap(body: dict):
    return body.get("data", body)


# ── Tunnel handle ─────────────────────────────────────────────────────────────

@dataclass
class Tunnel:
    """Handle to a running tunnel process."""
    url: str
    port: int
    _proc: subprocess.Popen = field(repr=False)

    def stop(self) -> None:
        """Terminate the tunnel process."""
        try:
            self._proc.terminate()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop()

    def __repr__(self):
        return f"Tunnel(url={self.url!r}, port={self.port})"


# ── expose() ─────────────────────────────────────────────────────────────────

def expose(
    port: int,
    *,
    token: Optional[str] = None,
    expire: Optional[str] = None,
    daemon: bool = False,
    no_qr: bool = True,
    binary: Optional[str] = None,
    timeout: float = 30.0,
) -> Tunnel:
    """
    Expose ``port`` via the mekong binary.

    Returns a :class:`Tunnel` whose ``.url`` is the public HTTPS address.
    Use as a context manager or call ``.stop()`` when done.

    Parameters
    ----------
    port    : local port to expose
    token   : API token (falls back to MEKONG_TOKEN env or saved login)
    expire  : lifetime, e.g. "2h", "1d"
    daemon  : run tunnel in background (-d flag)
    no_qr   : suppress QR code output (default True in SDK mode)
    binary  : explicit path to mekong binary
    timeout : seconds to wait for the tunnel URL (default 30)
    """
    mekong_bin = binary or shutil.which("mekong")
    if not mekong_bin:
        # common install locations
        for candidate in [
            Path.home() / "bin" / "mekong",
            Path.home() / ".local" / "bin" / "mekong",
            Path("/usr/local/bin/mekong"),
            Path("/usr/bin/mekong"),
        ]:
            if candidate.exists():
                mekong_bin = str(candidate)
                break
    if not mekong_bin:
        raise FileNotFoundError(
            "mekong binary not found. "
            "Install from https://github.com/MuyleangIng/MekongTunnel/releases"
        )

    resolved_token = token or get_token()

    args = [mekong_bin, str(port)]
    if expire:
        args += ["--expire", expire]
    if resolved_token:
        args += ["--token", resolved_token]
    if daemon:
        args.append("-d")
    if no_qr:
        args.append("--no-qr")

    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, bufsize=1)

    url_found: list[str] = []
    error_ev = threading.Event()

    import re
    # Strip ANSI codes first, then extract clean URLs
    _ansi_re = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
    url_re   = re.compile(r"https?://[a-zA-Z0-9][a-zA-Z0-9\-./]*[a-zA-Z0-9]")

    def _reader(stream):
        for line in stream:
            if not url_found:
                clean = _ansi_re.sub("", line)
                m = url_re.search(clean)
                if m:
                    url_found.append(m.group(0))

    t_out = threading.Thread(target=_reader, args=(proc.stdout,), daemon=True)
    t_err = threading.Thread(target=_reader, args=(proc.stderr,), daemon=True)
    t_out.start()
    t_err.start()

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if url_found:
            return Tunnel(url=url_found[0], port=port, _proc=proc)
        if proc.poll() is not None:
            raise RuntimeError(f"mekong exited with code {proc.returncode} before tunnel was ready")
        time.sleep(0.2)

    proc.terminate()
    raise TimeoutError(f"Timed out waiting for tunnel URL after {timeout}s")


# ── login() ──────────────────────────────────────────────────────────────────

def login(*, open_browser: bool = True) -> str:
    """
    Authenticate via the browser device flow.

    Opens ``angkorsearch.dev/cli-auth`` in the browser, polls until the user
    approves, then saves the token to ``~/.mekong/config.json``.

    Returns the raw API token string.
    """
    print("\nConnecting to angkorsearch.dev...", flush=True)

    try:
        raw = _api_post("/api/cli/device")
    except urllib.error.URLError as e:
        raise ConnectionError(f"Could not reach API: {e}") from e

    sess = _unwrap(raw)
    session_id  = sess["session_id"]
    login_url   = sess["login_url"]
    poll_interval = max(int(sess.get("poll_interval", 3)), 2)

    print(f"\n  Open this URL to log in:\n  \033[35m{login_url}\033[0m\n")

    if open_browser:
        try:
            webbrowser.open(login_url)
        except Exception:
            pass

    print("  Waiting for authorization", end="", flush=True)

    deadline = time.monotonic() + 5 * 60  # 5-minute window
    while time.monotonic() < deadline:
        time.sleep(poll_interval)
        try:
            pb = _api_get(f"/api/cli/device?session_id={session_id}")
        except Exception:
            print(".", end="", flush=True)
            continue

        poll = _unwrap(pb)
        status = poll.get("status")

        if status == "approved" and poll.get("token"):
            token = poll["token"]
            _save_config({"token": token})
            print("\n\n  \033[32m✔  Logged in!\033[0m\n")
            return token

        if status == "expired":
            raise RuntimeError("Session expired — call login() again")

        print(".", end="", flush=True)

    raise TimeoutError("Login timed out — call login() again")


# ── logout() ─────────────────────────────────────────────────────────────────

def logout() -> None:
    """Remove saved credentials from ~/.mekong/config.json."""
    try:
        _config_path().unlink()
        print("  Logged out.")
    except FileNotFoundError:
        print("  Already logged out.")


# ── whoami() ─────────────────────────────────────────────────────────────────

def whoami() -> Optional[dict]:
    """Return saved auth config dict or None if not logged in."""
    return _load_config()
