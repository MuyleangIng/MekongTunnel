"""
Framework-specific entry points.

Each command follows the pattern:
  <framework>-mekong [--mekong-flags] <framework-args...>

Mekong flags (stripped before passing to the framework):
  --expire <val>   Tunnel expiry (e.g. 2h, 1d)
  --token <tok>    API token for reserved subdomain (env: MEKONG_TOKEN)
  --no-qr          Suppress QR code
  --daemon         Run tunnel in background
  --local          Start server, open localhost in browser (no tunnel)
  --domain         Start server + tunnel, open public URL in browser
  --help, -h       Show help

Everything else is forwarded verbatim to the framework command.
"""

import os
import shutil
import sys

from .detect_port import detect_port
from .find_mekong import find_mekong
from .runner import run

BOLD  = '\033[1m'
CYAN  = '\033[36m'
DIM   = '\033[2m'
RED   = '\033[31m'
RESET = '\033[0m'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_server_cmd(binary, module=None):
    """Return [binary] if on PATH, else [sys.executable, '-m', module]."""
    if shutil.which(binary):
        return [binary]
    return [sys.executable, '-m', module or binary.replace('-', '_')]


def _parse_flags(argv: list):
    """
    Split argv into (opts, server_args).
    opts keys: expire, no_qr, daemon, local, domain
    server_args: everything not consumed as a mekong flag.
    """
    opts = {'expire': None, 'token': None, 'no_qr': False, 'daemon': False,
            'local': False, 'domain': False}
    i = 0
    while i < len(argv):
        t = argv[i]
        if t == '--expire':
            if i + 1 >= len(argv):
                print(f'{RED}--expire requires a value (e.g. --expire 2h){RESET}',
                      file=sys.stderr)
                sys.exit(1)
            opts['expire'] = argv[i + 1]
            i += 2
        elif t.startswith('--expire='):
            opts['expire'] = t.split('=', 1)[1]
            i += 1
        elif t == '--token':
            if i + 1 >= len(argv):
                print(f'{RED}--token requires a value{RESET}', file=sys.stderr)
                sys.exit(1)
            opts['token'] = argv[i + 1]
            i += 2
        elif t.startswith('--token='):
            opts['token'] = t.split('=', 1)[1]
            i += 1
        elif t == '--no-qr':
            opts['no_qr'] = True
            i += 1
        elif t == '--daemon':
            opts['daemon'] = True
            i += 1
        elif t == '--local':
            opts['local'] = True
            i += 1
        elif t == '--domain':
            opts['domain'] = True
            i += 1
        else:
            # First unrecognised token — rest goes to framework
            return opts, argv[i:]
    return opts, []


def _make_main(framework, default_port, get_prefix, help_text):
    """
    Factory that returns a main() function for a specific framework command.

    framework     : display name (e.g. 'uvicorn')
    default_port  : fallback port if not detected from server args
    get_prefix    : callable() → list of strings prepended to server args
    help_text     : --help output
    """
    def main():
        argv = sys.argv[1:]

        if not argv or argv[0] in ('--help', '-h'):
            print(help_text)
            sys.exit(0)

        opts, server_args = _parse_flags(argv)

        if opts['local'] and opts['domain']:
            print(f'{RED}Error: --local and --domain are mutually exclusive.{RESET}',
                  file=sys.stderr)
            sys.exit(1)

        prefix         = get_prefix()
        full_server    = prefix + server_args
        port           = detect_port(server_args) or default_port

        # Resolve API token: flag > env var
        api_token = opts['token'] or os.environ.get('MEKONG_TOKEN', '').strip() or None

        # Build mekong extra flags
        extra_flags = []
        if opts['expire']:
            extra_flags += ['--expire', opts['expire']]
        if api_token:
            extra_flags += ['--token', api_token]
        if opts['no_qr']:
            extra_flags.append('--no-qr')
        if opts['daemon']:
            extra_flags.append('-d')

        # Determine mode
        mode = 'local' if opts['local'] else ('domain' if opts['domain'] else 'tunnel')

        # Find mekong binary (not needed in local mode)
        mekong_bin = None
        if mode != 'local':
            mekong_bin = find_mekong()
            if not mekong_bin:
                print(
                    f'{RED}Error: mekong binary not found.{RESET}\n'
                    f'Install from: https://github.com/MuyleangIng/MekongTunnel/releases\n'
                    f'Quick install (Linux/macOS):\n'
                    f'  curl -fsSL https://github.com/MuyleangIng/MekongTunnel'
                    f'/releases/latest/download/mekong-$(uname -s | tr A-Z a-z)-$(uname -m)'
                    f' -o ~/.local/bin/mekong && chmod +x ~/.local/bin/mekong',
                    file=sys.stderr,
                )
                sys.exit(1)

        run(full_server, port, mekong_bin, extra_flags, mode=mode, framework=framework)

    return main


# ---------------------------------------------------------------------------
# Per-framework help templates
# ---------------------------------------------------------------------------

def _help(name, default_port, examples):
    ex = '\n'.join(f'  {e}' for e in examples)
    return f"""{BOLD}{name}-mekong{RESET} — {name} + Mekong tunnel in one command

{BOLD}USAGE{RESET}
  {name}-mekong [OPTIONS] <{name}-args...>

{BOLD}OPTIONS{RESET}  (consumed by mekong-tunnel, not forwarded to {name})
  --expire <val>   Tunnel expiry  e.g. 2h, 30m, 1d, 1w
  --token <tok>    API token for reserved subdomain (env: MEKONG_TOKEN)
  --no-qr          Suppress QR code output
  --daemon         Run tunnel in background
  --local          Start server only, open {CYAN}http://localhost:{default_port}{RESET} in browser
  --domain         Start server + tunnel, open {CYAN}public URL{RESET} in browser
  --help, -h       Show this help

{BOLD}EXAMPLES{RESET}
{ex}

{BOLD}INSTALL MEKONG BINARY{RESET}
  https://github.com/MuyleangIng/MekongTunnel/releases
"""


# ---------------------------------------------------------------------------
# Entry points
# ---------------------------------------------------------------------------

def uvicorn_main():
    _make_main(
        framework='uvicorn',
        default_port=8000,
        get_prefix=lambda: _find_server_cmd('uvicorn'),
        help_text=_help('uvicorn', 8000, [
            'uvicorn-mekong main:app                        # tunnel on default port 8000',
            'uvicorn-mekong main:app --reload --port 8080   # custom port with reload',
            'uvicorn-mekong main:app --local                # localhost only, open browser',
            'uvicorn-mekong main:app --domain               # tunnel + open public URL',
            'uvicorn-mekong main:app --expire 2h --domain   # tunnel with expiry + browser',
            'uvicorn-mekong main:app --no-qr                # suppress QR code',
        ]),
    )()


def fastapi_main():
    """fastapi-mekong is an alias for uvicorn-mekong."""
    _make_main(
        framework='uvicorn',
        default_port=8000,
        get_prefix=lambda: _find_server_cmd('uvicorn'),
        help_text=_help('fastapi', 8000, [
            'fastapi-mekong main:app                        # FastAPI + tunnel',
            'fastapi-mekong main:app --reload               # with hot-reload',
            'fastapi-mekong main:app --local                # localhost only, open browser',
            'fastapi-mekong main:app --domain               # tunnel + open public URL',
        ]),
    )()


def flask_main():
    _make_main(
        framework='flask',
        default_port=5000,
        get_prefix=lambda: _find_server_cmd('flask', 'flask'),
        help_text=_help('flask', 5000, [
            'flask-mekong run                               # tunnel on default port 5000',
            'flask-mekong run --port 5001                   # custom port',
            'flask-mekong run --local                       # localhost only, open browser',
            'flask-mekong run --domain                      # tunnel + open public URL',
            'flask-mekong run --expire 1d                   # tunnel expires in 1 day',
        ]),
    )()


def gunicorn_main():
    _make_main(
        framework='gunicorn',
        default_port=8000,
        get_prefix=lambda: _find_server_cmd('gunicorn'),
        help_text=_help('gunicorn', 8000, [
            'gunicorn-mekong app:app                        # tunnel on default port 8000',
            'gunicorn-mekong app:app --bind 0.0.0.0:8080    # custom port',
            'gunicorn-mekong app:app -w 4                   # 4 workers + tunnel',
            'gunicorn-mekong app:app --local                # localhost only, open browser',
            'gunicorn-mekong app:app --domain               # tunnel + open public URL',
        ]),
    )()


def django_main():
    _make_main(
        framework='django',
        default_port=8000,
        get_prefix=lambda: [sys.executable, 'manage.py'],
        help_text=_help('django', 8000, [
            'django-mekong runserver                        # tunnel on default port 8000',
            'django-mekong runserver 8080                   # custom port',
            'django-mekong runserver 0.0.0.0:8000           # bind all interfaces',
            'django-mekong runserver --local                # localhost only, open browser',
            'django-mekong runserver --domain               # tunnel + open public URL',
        ]),
    )()


def hypercorn_main():
    _make_main(
        framework='hypercorn',
        default_port=8000,
        get_prefix=lambda: _find_server_cmd('hypercorn'),
        help_text=_help('hypercorn', 8000, [
            'hypercorn-mekong main:app                      # tunnel on default port 8000',
            'hypercorn-mekong main:app --bind 0.0.0.0:8080  # custom port',
            'hypercorn-mekong main:app --local              # localhost only, open browser',
            'hypercorn-mekong main:app --domain             # tunnel + open public URL',
        ]),
    )()


def granian_main():
    _make_main(
        framework='granian',
        default_port=8000,
        get_prefix=lambda: _find_server_cmd('granian'),
        help_text=_help('granian', 8000, [
            'granian-mekong main:app                        # tunnel on default port 8000',
            'granian-mekong main:app --port 8080            # custom port',
            'granian-mekong main:app --local                # localhost only, open browser',
            'granian-mekong main:app --domain               # tunnel + open public URL',
        ]),
    )()
