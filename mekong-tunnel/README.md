# mekong-tunnel

> Expose your Python dev server to the internet in one command.
> Works with FastAPI, Flask, Django, Gunicorn, Uvicorn, Hypercorn, and Granian.

[![PyPI version](https://img.shields.io/pypi/v/mekong-tunnel)](https://pypi.org/project/mekong-tunnel/)
[![Python versions](https://img.shields.io/pypi/pyversions/mekong-tunnel)](https://pypi.org/project/mekong-tunnel/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## How it works

`mekong-tunnel` installs framework-specific commands that start your dev server **and** open a public tunnel via [mekongtunnel.dev](https://mekongtunnel.dev) — all in a single command.

```
uvicorn-mekong main:app --reload
```

```
 uvicorn-mekong  cmd: uvicorn main:app --reload  port: 8000  mode: tunnel

[uvicorn] INFO:     Uvicorn running on http://127.0.0.1:8000
✔  uvicorn is up on port 8000.
[tunnel]  ✔  Tunnel is live!
[tunnel]     URL  https://happy-tiger-a1b2c3d4.mekongtunnel.dev

╔═══════════════════════════════════════════════════════════════╗
║  Public URL: https://happy-tiger-a1b2c3d4.mekongtunnel.dev   ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## Installation

```bash
pip install mekong-tunnel
```

> **Requires the `mekong` binary** — install it separately:
>
> ```bash
> # macOS / Linux (auto-detect arch)
> curl -fsSL https://github.com/MuyleangIng/MekongTunnel/releases/latest/download/mekong-$(uname -s | tr A-Z a-z)-$(uname -m) \
>   -o ~/.local/bin/mekong && chmod +x ~/.local/bin/mekong
>
> # Windows — download from:
> # https://github.com/MuyleangIng/MekongTunnel/releases/latest
> ```

---

## Commands

| Command | Framework | Default port |
|---|---|---|
| `uvicorn-mekong` | Uvicorn / FastAPI | 8000 |
| `fastapi-mekong` | FastAPI (alias for uvicorn) | 8000 |
| `flask-mekong` | Flask | 5000 |
| `gunicorn-mekong` | Gunicorn | 8000 |
| `django-mekong` | Django | 8000 |
| `hypercorn-mekong` | Hypercorn | 8000 |
| `granian-mekong` | Granian | 8000 |

---

## Modes

Each command supports three modes:

| Flag | Mode | What happens |
|---|---|---|
| _(none)_ | **tunnel** | Start server + open public tunnel, print URL |
| `--local` | **local** | Start server only, open `http://localhost:{port}` in browser |
| `--domain` | **domain** | Start server + tunnel, open public URL in browser |

---

## Usage

### FastAPI / Uvicorn

```bash
# Default: start server + tunnel, print public URL
uvicorn-mekong main:app

# With hot-reload and custom port
uvicorn-mekong main:app --reload --port 8080

# Open localhost in browser (no tunnel)
uvicorn-mekong main:app --local

# Open public URL in browser automatically
uvicorn-mekong main:app --domain

# Tunnel with 2-hour expiry
uvicorn-mekong main:app --expire 2h

# fastapi-mekong is identical to uvicorn-mekong
fastapi-mekong main:app --reload --domain
```

### Flask

```bash
flask-mekong run                        # port 5000 + tunnel
flask-mekong run --port 5001            # custom port
flask-mekong run --local                # localhost only, open browser
flask-mekong run --domain               # tunnel + open public URL
flask-mekong run --expire 1d            # expires in 1 day
```

### Django

```bash
django-mekong runserver                 # port 8000 + tunnel
django-mekong runserver 8080            # custom port
django-mekong runserver 0.0.0.0:8000   # bind all interfaces
django-mekong runserver --local         # localhost only, open browser
django-mekong runserver --domain        # tunnel + open public URL
```

### Gunicorn

```bash
gunicorn-mekong app:app                        # port 8000 + tunnel
gunicorn-mekong app:app --bind 0.0.0.0:8080    # custom port
gunicorn-mekong app:app -w 4                   # 4 workers + tunnel
gunicorn-mekong app:app --domain               # tunnel + open public URL
```

### Hypercorn

```bash
hypercorn-mekong main:app                      # port 8000 + tunnel
hypercorn-mekong main:app --bind 0.0.0.0:8080  # custom port
hypercorn-mekong main:app --domain             # tunnel + open public URL
```

### Granian

```bash
granian-mekong main:app                        # port 8000 + tunnel
granian-mekong main:app --port 8080            # custom port
granian-mekong main:app --domain               # tunnel + open public URL
```

---

## All mekong-tunnel flags

These flags are consumed by `mekong-tunnel` and **not** forwarded to your framework:

| Flag | Description |
|---|---|
| `--local` | No tunnel — open localhost in browser |
| `--domain` | Tunnel + open public URL in browser |
| `--expire <val>` | Tunnel expiry: `30m`, `2h`, `1d`, `1w` |
| `--no-qr` | Suppress QR code in terminal |
| `--daemon` | Run tunnel in background |
| `--help`, `-h` | Show help |

All other flags are forwarded verbatim to your framework.

---

## Quick test (FastAPI)

```bash
pip install fastapi uvicorn mekong-tunnel

cat > main.py << 'EOF'
from fastapi import FastAPI
app = FastAPI()

@app.get("/")
def root():
    return {"message": "Hello from Mekong Tunnel!"}
EOF

uvicorn-mekong main:app --reload
```

---

## How it works internally

1. **Start your server** as a subprocess
2. **Poll the port** until it accepts connections (30 s timeout)
3. **Spawn `mekong`** tunnel to the detected port
4. **Stream both** outputs to your terminal
5. **On URL detected** — print banner (and open browser if `--domain`)
6. **Clean shutdown** on `Ctrl+C` — stops both processes

---

## Requirements

- Python 3.8+
- `mekong` binary on PATH ([download](https://github.com/MuyleangIng/MekongTunnel/releases))
- No other Python dependencies

---

## License

MIT © [Ing Muyleang](https://github.com/MuyleangIng) — KhmerStack
