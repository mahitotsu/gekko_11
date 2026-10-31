"""事務サービス（insurer-mcp）。営業 AI エージェントが MCP で呼ぶ窓口（architecture の 2 章）。

トークンは、受け口の token-guard が確かめ、出口の token-guard が替える（2-2）。このアプリは、トークンも証明書も持たない。
受け口で受けた控えの番号（x-auth-ctx）を、保険会社のシステムへの出口の呼び出しに付けて送る。
ツールの呼び出しは、1 件ずつ記録として標準出力に書く（D-17）。
"""

import base64
import json
import os
import sys
import time
from typing import Any

import httpx2 as httpx
from fastmcp import FastMCP
from fastmcp.server.dependencies import get_http_headers

BACKEND = os.environ.get("BACKEND_EGRESS_URL", "http://127.0.0.1:15102")
NAMESPACE = os.environ.get("NAMESPACE", "secure")

mcp = FastMCP("insurer-mcp")

# テストで差し替えられるよう、保険会社のシステムへの呼び出しは 1 か所にまとめる
transport: httpx.AsyncBaseTransport | None = None


def _incoming() -> dict[str, str]:
    return get_http_headers(include={"x-auth-ctx", "x-auth-claims"})


def _record(tool: str, detail: dict[str, Any]) -> None:
    """ツールの呼び出しの記録。誰の依頼か（sub）と、誰が取り次いだか（act）を、トークンの主張から書く。"""
    claims: dict[str, Any] = {}
    raw = _incoming().get("x-auth-claims")
    if raw:
        claims = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))).get("claims", {})
    record = {"at": int(time.time()), "service": "insurer-mcp", "tool": tool, "sub": claims.get("sub"),
              "act": claims.get("act"), "jti": claims.get("jti"), **detail}
    print(json.dumps({"tool_call": record}, ensure_ascii=False), file=sys.stdout, flush=True)


async def _backend(method: str, path: str, **kwargs: Any) -> Any:
    headers = {"x-auth-ctx": _incoming().get("x-auth-ctx", "")}
    async with httpx.AsyncClient(base_url=BACKEND, transport=transport, timeout=10) as client:
        response = await client.request(method, path, headers=headers, **kwargs)
    try:
        body = response.json()
    except ValueError:
        body = {"error": response.text}
    return {"status": response.status_code, **body} if response.status_code >= 400 else body


@mcp.tool
async def get_offers(on_behalf_of: str | None = None) -> Any:
    """保険会社が署名した案の一式と、提示集合の識別子、nonce を取る。on_behalf_of は窓口の申告で、保険会社のシステムは信じない。"""
    result = await _backend("POST", "/offers", json={"for_user": on_behalf_of} if on_behalf_of else {})
    _record("get_offers", {"nonce": result.get("nonce") if isinstance(result, dict) else None})
    return result


@mcp.tool
async def list_contracts(on_behalf_of: str | None = None) -> Any:
    """契約の一覧を照会する。"""
    params = {"for_user": on_behalf_of} if on_behalf_of else {}
    result = await _backend("GET", "/contracts", params=params)
    _record("list_contracts", {})
    return result


@mcp.tool
async def submit_application(intent: dict[str, Any], application: dict[str, Any], assertion: Any,
                             intent_assertion: Any = None, offer_jws: str | None = None,
                             extras: dict[str, Any] | None = None) -> Any:
    """顧客が署名した意向確認と申込みを、保険会社のシステムへ回す。extras は窓口が足せる欄で、保険会社のシステムは信じない。"""
    body = {"offerJws": offer_jws, "intent": intent, "intentAssertion": intent_assertion,
            "application": application, "assertion": assertion, **(extras or {})}
    result = await _backend("POST", "/applications", json=body)
    _record("submit_application", {"nonce": application.get("nonce"),
                                   "contractId": (result.get("contract") or {}).get("contractId")
                                   if isinstance(result, dict) else None})
    return result


def create_app():
    return mcp.http_app(path="/mcp", stateless_http=True, json_response=True,
                        allowed_hosts=[f"insurer-mcp.{NAMESPACE}.svc:9443", "127.0.0.1:8080", "localhost:8080"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=int(os.environ.get("APP_PORT", "8080")))
