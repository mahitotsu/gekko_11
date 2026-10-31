"""事務サービスのツールが、受け口の控えの番号を付けて保険会社のシステムへ回し、記録を書くことを確かめる。"""

import json

import httpx2 as httpx
import pytest
from fastmcp import Client

from insurer_mcp import app


@pytest.fixture
def backend(monkeypatch):
    calls = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/offers":
            return httpx.Response(200, json={"nonce": "n-1", "offerJws": "jws"})
        if request.url.path == "/applications":
            return httpx.Response(200, json={"ok": True, "contract": {"contractId": "C-1"}})
        return httpx.Response(403, json={"error": "利用者本人のトークンではない"})

    monkeypatch.setattr(app, "transport", httpx.MockTransport(handle))
    monkeypatch.setattr(app, "_incoming", lambda: {"x-auth-ctx": "ctx-1", "x-auth-claims": claims()})
    return calls


def claims() -> str:
    import base64

    raw = json.dumps({"claims": {"sub": "alice", "act": {"sub": "sales-agent"}, "jti": "j-1"}}).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


async def test_tools_forward_the_context_handle_not_a_token(backend):
    async with Client(app.mcp) as client:
        await client.call_tool("get_offers", {})
    assert backend[0].headers["x-auth-ctx"] == "ctx-1"
    assert "authorization" not in backend[0].headers


async def test_submit_application_passes_extras_and_records_the_call(backend, capsys):
    async with Client(app.mcp) as client:
        result = await client.call_tool("submit_application", {
            "intent": {"nonce": "n-1"}, "application": {"nonce": "n-1"}, "assertion": {},
            "extras": {"contact": "http://elsewhere"}})
    sent = json.loads(backend[-1].content)
    assert sent["contact"] == "http://elsewhere"
    assert result.data["contract"]["contractId"] == "C-1"
    record = json.loads(capsys.readouterr().out.strip().splitlines()[-1])["tool_call"]
    assert record["tool"] == "submit_application"
    assert record["sub"] == "alice"
    assert record["act"] == {"sub": "sales-agent"}
    assert record["contractId"] == "C-1"


async def test_backend_refusal_is_returned_with_its_status(backend):
    async with Client(app.mcp) as client:
        result = await client.call_tool("list_contracts", {})
    assert result.data["status"] == 403
