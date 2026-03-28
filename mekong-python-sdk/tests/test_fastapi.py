"""
mekong-tunnel × FastAPI integration test
Run: pytest tests/test_fastapi.py -v

Starts a real FastAPI app on a free port, exposes it via mekong-tunnel,
then verifies the public URL is reachable from the internet.

Requirements:
  pip install fastapi uvicorn httpx
  mekong binary installed (https://mekongtunnel.dev/docs/installation)

Skip conditions:
  - mekong binary not found  → all tests skipped
  - uvicorn/fastapi missing   → all tests skipped
"""

import socket
import threading
import time
import urllib.request

import pytest

# ─── Skip guard ────────────────────────────────────────────────────────────────

def _binary_available() -> bool:
    try:
        from mekong_tunnel.find_mekong import find_mekong
        find_mekong()
        return True
    except Exception:
        return False

def _uvicorn_available() -> bool:
    try:
        import uvicorn
        import fastapi
        return True
    except ImportError:
        return False

NEEDS_BINARY  = pytest.mark.skipif(not _binary_available(),  reason="mekong binary not installed")
NEEDS_UVICORN = pytest.mark.skipif(not _uvicorn_available(), reason="fastapi/uvicorn not installed — pip install fastapi uvicorn")


# ─── Fixtures ─────────────────────────────────────────────────────────────────

def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def fastapi_server():
    """
    Spin up a minimal FastAPI app in a background thread and yield its port.
    Tears down after the test module completes.
    """
    try:
        from fastapi import FastAPI
        import uvicorn
    except ImportError:
        pytest.skip("fastapi/uvicorn not installed")

    app = FastAPI(title="mekong-test")

    @app.get("/")
    def root():
        return {"service": "mekong-test", "status": "ok"}

    @app.get("/ping")
    def ping():
        return {"pong": True}

    @app.get("/items/{item_id}")
    def item(item_id: int):
        return {"id": item_id, "name": f"item-{item_id}"}

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to be ready
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/ping", timeout=1)
            break
        except Exception:
            time.sleep(0.2)

    yield port

    server.should_exit = True


@pytest.fixture(scope="module")
def mekong_tunnel(fastapi_server):
    """
    Expose the FastAPI server via mekong-tunnel and yield the public URL.
    Waits up to 10s for the tunnel to become reachable before handing off.
    """
    import mekong_tunnel as mekong
    tunnel = mekong.expose(fastapi_server, no_qr=True, timeout=25)
    # Give the SSH tunnel a moment to stabilize
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            urllib.request.urlopen(tunnel.url + "/", timeout=3)
            break
        except Exception:
            time.sleep(1)
    yield tunnel
    tunnel.stop()


# ─── Tests ─────────────────────────────────────────────────────────────────────

@NEEDS_BINARY
@NEEDS_UVICORN
class TestFastAPILocal:
    """Tests that the local FastAPI server itself works before tunneling."""

    def test_local_root_returns_ok(self, fastapi_server):
        url = f"http://127.0.0.1:{fastapi_server}/"
        with urllib.request.urlopen(url, timeout=5) as resp:
            assert resp.status == 200

    def test_local_ping(self, fastapi_server):
        import json
        url = f"http://127.0.0.1:{fastapi_server}/ping"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        assert data["pong"] is True

    def test_local_item_endpoint(self, fastapi_server):
        import json
        url = f"http://127.0.0.1:{fastapi_server}/items/42"
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read())
        assert data["id"] == 42


@NEEDS_BINARY
@NEEDS_UVICORN
class TestFastAPITunnel:
    """Tests that the FastAPI app is reachable through the mekong tunnel."""

    def test_tunnel_url_is_https(self, mekong_tunnel):
        assert mekong_tunnel.url.startswith("https://"), \
            f"Expected https URL, got: {mekong_tunnel.url}"

    def test_tunnel_url_is_proxy_angkorsearch_dev(self, mekong_tunnel):
        assert ".proxy.angkorsearch.dev" in mekong_tunnel.url, \
            f"Unexpected domain in: {mekong_tunnel.url}"

    def test_tunnel_root_reachable(self, mekong_tunnel):
        import json
        url = mekong_tunnel.url + "/"
        with urllib.request.urlopen(url, timeout=15) as resp:
            assert resp.status == 200
            data = json.loads(resp.read())
        assert data["status"] == "ok"

    def test_tunnel_ping_reachable(self, mekong_tunnel):
        import json
        url = mekong_tunnel.url + "/ping"
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read())
        assert data["pong"] is True

    def test_tunnel_dynamic_route(self, mekong_tunnel):
        import json
        url = mekong_tunnel.url + "/items/7"
        with urllib.request.urlopen(url, timeout=15) as resp:
            data = json.loads(resp.read())
        assert data["id"] == 7
        assert data["name"] == "item-7"

    def test_tunnel_stop_does_not_crash(self, mekong_tunnel):
        # tunnel.stop() is called by the fixture teardown — just check it's callable
        assert callable(mekong_tunnel.stop)


# ─── auth/token integration ────────────────────────────────────────────────────

@NEEDS_BINARY
@NEEDS_UVICORN
class TestFastAPITunnelWithToken:
    """
    Same tunnel tests but with an explicit token (reserved subdomain).
    Skipped automatically when no token is configured.
    """

    @pytest.fixture(scope="class")
    def token_tunnel(self, fastapi_server):
        import mekong_tunnel as mekong
        token = mekong.get_token()
        if not token:
            pytest.skip("no token — run: mekong login   or set MEKONG_TOKEN env var")
        tunnel = mekong.expose(fastapi_server, token=token, no_qr=True, timeout=25)
        yield tunnel
        tunnel.stop()

    def test_token_tunnel_url_is_https(self, token_tunnel):
        assert token_tunnel.url.startswith("https://")

    def test_token_tunnel_root_reachable(self, token_tunnel):
        import json
        with urllib.request.urlopen(token_tunnel.url + "/", timeout=15) as resp:
            data = json.loads(resp.read())
        assert data["status"] == "ok"
