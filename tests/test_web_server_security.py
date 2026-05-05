from __future__ import annotations

import inspect
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import openharness.config as config_module
import openharness.web_server as web_server


class _FakeSettings:
    def __init__(self) -> None:
        self.permission = SimpleNamespace(
            mode="default",
            allowed_tools=[],
            denied_tools=[],
            path_rules=[],
            denied_commands=[],
        )
        self.model = "test-model"
        self.theme = "dark"
        self.output_style = "default"
        self.vim_mode = False
        self.voice_mode = False
        self.effort = "medium"
        self.passes = 1
        self.max_turns = None


class _FakeAppState:
    def __init__(self, events: list[tuple]) -> None:
        self._events = events
        self._state = SimpleNamespace(permission_mode="default", model="test-model", cwd="/tmp")

    def get(self):
        return self._state

    def set(self, **kwargs):
        self._events.append(("app_state.set", kwargs))
        for key, value in kwargs.items():
            setattr(self._state, key, value)


class _FakeEngine:
    def __init__(self, events: list[tuple]) -> None:
        self._events = events

    def set_permission_checker(self, checker) -> None:
        self._events.append(("engine.set_permission_checker", type(checker).__name__))

    def set_model(self, model: str) -> None:
        self._events.append(("engine.set_model", model))


class _FakeBundle:
    def __init__(self, events: list[tuple]) -> None:
        self.app_state = _FakeAppState(events)
        self.engine = _FakeEngine(events)

    def current_settings(self):
        return _FakeSettings()


def _install_fake_runtime(monkeypatch):
    events: list[tuple] = []

    async def fake_handle_request(sio, sid, payload):
        events.append(("handle_request", sid, payload))

    async def fake_broadcast(message):
        events.append(("broadcast", message.get("type")))

    monkeypatch.setattr(config_module, "load_settings", lambda: _FakeSettings())
    monkeypatch.setattr(
        config_module,
        "save_settings",
        lambda settings: events.append(
            ("save_settings", getattr(settings.permission, "mode", None))
        ),
    )
    monkeypatch.setattr(web_server.backend_host, "handle_request", fake_handle_request)
    monkeypatch.setattr(web_server.backend_host, "broadcast", fake_broadcast)
    web_server.backend_host.runtime_bundle = _FakeBundle(events)
    return events


def test_web_server_defaults_to_loopback_binding():
    assert inspect.signature(web_server.run_web_server).parameters["host"].default == "127.0.0.1"


@pytest.mark.asyncio
async def test_web_server_rejects_network_bind_without_auth_token():
    with pytest.raises(ValueError, match="without authentication"):
        await web_server.run_web_server(host="0.0.0.0", serve_frontend=False)


def test_web_api_rejects_unauthenticated_control_plane_when_token_configured(monkeypatch):
    events = _install_fake_runtime(monkeypatch)
    app = web_server.create_app(cwd="/tmp", model="test-model", auth_token="secret-token")

    client = TestClient(app)

    health = client.get("/api/health")
    config = client.post("/api/config", json={"permission_mode": "auto"})
    submit = client.post("/api/submit", json={"line": "Use Bash to run: id > /tmp/pwned"})

    assert health.status_code == 200
    assert config.status_code == 401
    assert submit.status_code == 401
    assert events == []


def test_web_api_accepts_bearer_token_before_changing_runtime_state(monkeypatch):
    events = _install_fake_runtime(monkeypatch)
    app = web_server.create_app(cwd="/tmp", model="test-model", auth_token="secret-token")

    client = TestClient(app)
    headers = {"Authorization": "Bearer secret-token"}

    config = client.post("/api/config", json={"permission_mode": "auto"}, headers=headers)
    submit = client.post(
        "/api/submit",
        json={"line": "Use Bash to run: id > /tmp/openharness-web-pwned"},
        headers=headers,
    )
    time.sleep(0.05)

    assert config.status_code == 200
    assert submit.status_code == 200
    assert ("app_state.set", {"permission_mode": "full_auto"}) in events
    assert (
        "handle_request",
        None,
        {"type": "submit_line", "line": "Use Bash to run: id > /tmp/openharness-web-pwned"},
    ) in events
