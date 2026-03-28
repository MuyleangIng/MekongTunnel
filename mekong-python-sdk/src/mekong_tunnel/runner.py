"""
Core runner: spawn server + optional mekong tunnel.
Supports three modes:
  tunnel  — server + tunnel, print public URL banner (default)
  local   — server only, open localhost in browser
  domain  — server + tunnel, open public URL in browser
"""

import re
import signal
import socket
import subprocess
import sys
import threading
import time
import webbrowser

BOLD   = '\033[1m'
DIM    = '\033[2m'
CYAN   = '\033[36m'
GREEN  = '\033[32m'
YELLOW = '\033[33m'
RED    = '\033[31m'
RESET  = '\033[0m'

_URL_RE = re.compile(r'https?://\S+')


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stream(proc, prefix):
    try:
        for line in proc.stdout:
            print(f'{prefix} {line.rstrip()}{RESET}', flush=True)
    except ValueError:
        pass


def _url_stream(proc, prefix, on_url=None):
    """Stream tunnel output; call on_url(url) the first time a URL is seen."""
    found = False
    try:
        for line in proc.stdout:
            line = line.rstrip()
            print(f'{prefix} {line}{RESET}', flush=True)
            if not found:
                m = _URL_RE.search(line)
                if m:
                    url = m.group(0).rstrip('.')
                    found = True
                    _print_url_banner(url)
                    if on_url:
                        on_url(url)
    except ValueError:
        pass


def _print_url_banner(url: str):
    content = 'Public URL: ' + url
    width   = max(42, len(content) + 4)
    bar     = '=' * width
    pad     = ' ' * (width - len(content) - 1)
    print(f'\n{GREEN}{BOLD}'
          f'\u2554{bar}\u2557\n'
          f'\u2551  {content}{pad}\u2551\n'
          f'\u255a{bar}\u255d'
          f'{RESET}\n', flush=True)


def _wait_for_port(port: int, timeout: float = 30.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _spawn(cmd):
    try:
        return subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except FileNotFoundError:
        print(f'{RED}Error: command not found: {cmd[0]}{RESET}', file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run(server_args, port, mekong_bin,
        extra_flags=None, mode='tunnel', framework='server'):
    """
    """
    if extra_flags is None:
        extra_flags = []

    mode_label = {'tunnel': 'tunnel', 'local': 'localhost only', 'domain': 'tunnel + open browser'}[mode]

    print(
        f'\n{BOLD}{CYAN}{framework}-mekong{RESET}  '
        f'{DIM}cmd:{RESET} {" ".join(server_args)}  '
        f'{DIM}port:{RESET} {CYAN}{port}{RESET}  '
        f'{DIM}mode:{RESET} {CYAN}{mode_label}{RESET}\n',
        flush=True,
    )

    # ------------------------------------------------------------------
    # Spawn server
    # ------------------------------------------------------------------
    server_proc = _spawn(server_args)
    threading.Thread(
        target=_stream,
        args=(server_proc, DIM + f'[{framework}]' + RESET),
        daemon=True,
    ).start()

    # ------------------------------------------------------------------
    # Wait for port to open
    # ------------------------------------------------------------------
    print(f'{DIM}Waiting for {framework} on port {port}…{RESET}', flush=True)
    if not _wait_for_port(port):
        print(f'{RED}Timed out waiting for port {port} to open.{RESET}', file=sys.stderr)
        server_proc.terminate()
        sys.exit(1)
    print(f'{GREEN}✔  {framework} is up on port {port}.{RESET}', flush=True)

    # ------------------------------------------------------------------
    # LOCAL mode — no tunnel, just open browser at localhost
    # ------------------------------------------------------------------
    if mode == 'local':
        local_url = f'http://localhost:{port}'
        print(f'\n{CYAN}Opening {local_url} in browser…{RESET}\n', flush=True)
        webbrowser.open(local_url)

        def _shutdown_local(signum, frame):
            print(f'\n{YELLOW}Shutting down…{RESET}', flush=True)
            server_proc.terminate()
            sys.exit(0)

        signal.signal(signal.SIGINT,  _shutdown_local)
        signal.signal(signal.SIGTERM, _shutdown_local)
        server_proc.wait()
        sys.exit(server_proc.returncode or 0)

    # ------------------------------------------------------------------
    # TUNNEL / DOMAIN mode — spawn mekong
    # ------------------------------------------------------------------
    tunnel_cmd  = [mekong_bin, str(port)] + extra_flags
    tunnel_proc = _spawn(tunnel_cmd)

    open_browser = (mode == 'domain')

    def _on_url(url):
        if open_browser:
            print(f'\n{CYAN}Opening {url} in browser…{RESET}', flush=True)
            webbrowser.open(url)

    threading.Thread(
        target=_url_stream,
        args=(tunnel_proc, CYAN + '[tunnel]' + RESET, _on_url),
        daemon=True,
    ).start()

    # ------------------------------------------------------------------
    # Signal handlers
    # ------------------------------------------------------------------
    def _shutdown(signum, frame):
        print(f'\n{YELLOW}Shutting down…{RESET}', flush=True)
        tunnel_proc.terminate()
        server_proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ------------------------------------------------------------------
    # Monitor loop
    # ------------------------------------------------------------------
    while True:
        if tunnel_proc.poll() is not None:
            server_proc.terminate()
            sys.exit(tunnel_proc.returncode or 0)

        srv_ret = server_proc.poll()
        if srv_ret is not None and srv_ret != 0:
            print(f'{RED}Server exited with code {srv_ret}. Stopping tunnel.{RESET}', file=sys.stderr)
            tunnel_proc.terminate()
            sys.exit(srv_ret)

        time.sleep(0.5)
