"""
mekong-tunnel SDK tests
Run: pytest tests/test_sdk.py -v

Tests: get_token, whoami, logout, expose() with a live local server.

Set MEKONG_TOKEN env var or run `mekong login` first for authenticated tests.
Tunnel tests are automatically skipped when the mekong binary is not found.
"""

import json
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

import mekong_tunnel as mekong


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _free_port() -> int:
    """Return an available local TCP port."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _OkHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"hello from mekong-tunnel test")

    def log_message(self, *args):
        pass  # silence request logs during tests


def _start_local_server(port: int) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), _OkHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def _binary_available() -> bool:
    try:
        from mekong_tunnel.find_mekong import find_mekong
        find_mekong()
        return True
    except Exception:
        return False


BINARY_SKIP = pytest.mark.skipif(
    not _binary_available(),
    reason="mekong binary not installed — see https://mekongtunnel.dev/docs/installation",
)

TOKEN_SKIP = pytest.mark.skipif(
    not mekong.get_token(),
    reason="no token — run: mekong login   or set MEKONG_TOKEN env var",
)


# ─── Unit tests (no binary needed) ────────────────────────────────────────────

class TestGetToken:
    def test_returns_none_when_no_token(self, monkeypatch, tmp_path):
        monkeypatch.delenv("MEKONG_TOKEN", raising=False)
        # Point config to empty temp dir so no saved config is read
        monkeypatch.setattr("mekong_tunnel.sdk._config_path",
                            lambda: tmp_path / "config.json")
        tok = mekong.get_token()
        assert tok is None

    def test_reads_env_var(self, monkeypatch, tmp_path):
        monkeypatch.setenv("MEKONG_TOKEN", "mkt_env_test")
        monkeypatch.setattr("mekong_tunnel.sdk._config_path",
                            lambda: tmp_path / "config.json")
        tok = mekong.get_token()
        assert tok == "mkt_env_test"

    def test_env_takes_priority_over_config(self, monkeypatch, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"token": "mkt_from_file", "email": "x@x.com"}))
        monkeypatch.setenv("MEKONG_TOKEN", "mkt_from_env")
        monkeypatch.setattr("mekong_tunnel.sdk._config_path", lambda: cfg)
        tok = mekong.get_token()
        assert tok == "mkt_from_env"

    def test_reads_saved_config(self, monkeypatch, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"token": "mkt_saved", "email": "u@u.com"}))
        monkeypatch.delenv("MEKONG_TOKEN", raising=False)
        monkeypatch.setattr("mekong_tunnel.sdk._config_path", lambda: cfg)
        tok = mekong.get_token()
        assert tok == "mkt_saved"


class TestWhoami:
    def test_returns_none_when_no_config(self, monkeypatch, tmp_path):
        monkeypatch.delenv("MEKONG_TOKEN", raising=False)
        monkeypatch.setattr("mekong_tunnel.sdk._config_path",
                            lambda: tmp_path / "config.json")
        info = mekong.whoami()
        assert info is None

    def test_returns_dict_when_config_present(self, monkeypatch, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"token": "mkt_x", "email": "a@b.com"}))
        monkeypatch.setattr("mekong_tunnel.sdk._config_path", lambda: cfg)
        info = mekong.whoami()
        assert isinstance(info, dict)
        assert info["token"] == "mkt_x"
        assert info["email"] == "a@b.com"


class TestLogout:
    def test_logout_removes_config(self, monkeypatch, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"token": "mkt_x"}))
        monkeypatch.setattr("mekong_tunnel.sdk._config_path", lambda: cfg)
        mekong.logout()
        assert not cfg.exists()

    def test_logout_is_idempotent(self, monkeypatch, tmp_path):
        monkeypatch.setattr("mekong_tunnel.sdk._config_path",
                            lambda: tmp_path / "config.json")
        # Should not raise even if config doesn't exist
        mekong.logout()
        mekong.logout()


# ─── Integration tests (binary required) ──────────────────────────────────────

class TestExpose:
    @BINARY_SKIP
    def test_expose_returns_tunnel_with_url(self):
        port = _free_port()
        server = _start_local_server(port)
        tunnel = None
        try:
            tunnel = mekong.expose(port, no_qr=True, timeout=20)
            assert tunnel.url.startswith("https://"), f"Expected https URL, got: {tunnel.url}"
            assert ".proxy.angkorsearch.dev" in tunnel.url
        finally:
            if tunnel: tunnel.stop()
            server.server_close()

    @BINARY_SKIP
    def test_expose_stop_terminates_process(self):
        port = _free_port()
        server = _start_local_server(port)
        try:
            tunnel = mekong.expose(port, no_qr=True, timeout=20)
            assert tunnel._proc is not None
            tunnel.stop()
            # Give the process a moment to terminate
            time.sleep(0.3)
            assert tunnel._proc.poll() is not None, "Process should have terminated"
        finally:
            server.server_close()

    @BINARY_SKIP
    def test_expose_context_manager(self):
        port = _free_port()
        server = _start_local_server(port)
        proc_ref = None
        try:
            with mekong.expose(port, no_qr=True, timeout=20) as t:
                assert t.url.startswith("https://")
                proc_ref = t._proc
        finally:
            server.server_close()
        # After context exit, process should be terminated
        if proc_ref:
            time.sleep(0.3)
            assert proc_ref.poll() is not None, "Process should stop after context exit"

    @BINARY_SKIP
    @TOKEN_SKIP
    def test_expose_with_token(self):
        token = mekong.get_token()
        port = _free_port()
        server = _start_local_server(port)
        tunnel = None
        try:
            tunnel = mekong.expose(port, token=token, no_qr=True, timeout=20)
            assert tunnel.url.startswith("https://")
        finally:
            if tunnel: tunnel.stop()
            server.server_close()


# ─── mekong login/whoami/logout flow ──────────────────────────────────────────

class TestAuthFlow:
    """
    These tests verify the auth helpers work correctly with real or mock credentials.
    They do NOT open a browser — they test the config read/write layer only.
    """

    def test_whoami_token_field(self, monkeypatch, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({
            "token": "mkt_test123",
            "email": "user@example.com",
            "user_id": "uuid-abc",
        }))
        monkeypatch.setattr("mekong_tunnel.sdk._config_path", lambda: cfg)
        info = mekong.whoami()
        assert info is not None
        assert info["token"] == "mkt_test123"
        assert info["email"] == "user@example.com"

    def test_get_token_after_whoami(self, monkeypatch, tmp_path):
        cfg = tmp_path / "config.json"
        cfg.write_text(json.dumps({"token": "mkt_abc"}))
        monkeypatch.delenv("MEKONG_TOKEN", raising=False)
        monkeypatch.setattr("mekong_tunnel.sdk._config_path", lambda: cfg)
        assert mekong.get_token() == "mkt_abc"
        mekong.logout()
        assert mekong.get_token() is None
