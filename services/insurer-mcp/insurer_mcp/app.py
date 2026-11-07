"""事務サービス（insurer-mcp）。営業 AI エージェントが MCP で呼ぶ窓口（architecture の 2 章）。

トークンは、受け口の token-guard が確かめ、出口の token-guard が替える（2-2）。このアプリは、トークンも証明書も持たない。
受け口で受けた控えの番号（x-auth-ctx）を、保険会社のシステムへの出口の呼び出しに付けて送る。
ツールの呼び出しは、1 件ずつ記録として標準出力に書く（D-17）。
"""

import base64
import hashlib
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


def digest(value: Any) -> str:
    """JCS（RFC 8785）で正規化した内容の SHA-256 の base64url（D-1 の challenge と同じ値）。
    このシステムの書類は、文字列と整数と入れ子だけなので、鍵を並べ替えた空白のない JSON が、JCS と同じ並びになる。"""
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return base64.urlsafe_b64encode(hashlib.sha256(canonical.encode()).digest()).rstrip(b"=").decode()


def _record(tool: str, detail: dict[str, Any]) -> None:
    """ツールの呼び出しの記録（監査の形。D-17、D-30）。誰の依頼か（sub）と、誰が取り次いだか（act）を、トークンの主張から書く。
    Alloy が集め、名前空間の Loki に入れる。トークンと署名の値は書かない。"""
    claims: dict[str, Any] = {}
    raw = _incoming().get("x-auth-claims")
    if raw:
        claims = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))).get("claims", {})
    record = {"kind": "tool_call", "at": int(time.time()), "service": "insurer-mcp", "tool": tool, "sub": claims.get("sub"),
              "act": claims.get("act"), "jti": claims.get("jti"), **detail}
    print(json.dumps({"audit": record}, ensure_ascii=False), file=sys.stdout, flush=True)


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
async def get_products() -> Any:
    """商品の規則を取る。案を組み立てる前に読む。"""
    result = await _backend("GET", "/products")
    _record("get_products", {})
    return result


@mcp.tool
async def quote_plan(conditions: list[dict[str, Any]], on_behalf_of: str | None = None) -> Any:
    """条件（kind、termYears、payYears、monthly）から、年金の年額を試算する。署名はない。掛け金を変えて繰り返せる。
    示さなかった案も後から追えるように、全ての試算を記録に残す（P-17）。on_behalf_of は窓口の申告で、保険会社のシステムは信じない。"""
    result = await _backend("POST", "/quotes", json={"conditions": conditions, **({"for_user": on_behalf_of} if on_behalf_of else {})})
    _record("quote_plan", {"conditions": conditions, "quotes": result.get("quotes") if isinstance(result, dict) else None})
    return result


@mcp.tool
async def issue_offer(plans: list[dict[str, Any]], on_behalf_of: str | None = None) -> Any:
    """組み立てた案を提出する。保険会社のシステムが、規則と金額を確かめて署名する。合わなければ、理由を返す。"""
    result = await _backend("POST", "/offers", json={"plans": plans, **({"for_user": on_behalf_of} if on_behalf_of else {})})
    _record("issue_offer", {"plans": plans, "nonce": result.get("nonce") if isinstance(result, dict) else None,
                            "status": result.get("status", 200) if isinstance(result, dict) else None})
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
    # 取り次いだ申込みの案と顧客を残す。監査サービスが、保険会社のシステムの契約の記録と照らす
    # 申込みと意向確認のハッシュは、監査の突き合わせの根拠になる（保険会社の側で算出する。D-32）
    _record("submit_application", {"nonce": application.get("nonce"), "customer": application.get("customer"),
                                   "plan": application.get("plan"),
                                   "application_hash": digest(application), "intent_hash": digest(intent),
                                   "contractId": (result.get("contract") or {}).get("contractId")
                                   if isinstance(result, dict) else None,
                                   "status": result.get("status", 200) if isinstance(result, dict) else None})
    return result


def create_app():
    return mcp.http_app(path="/mcp", stateless_http=True, json_response=True,
                        allowed_hosts=[f"insurer-mcp.{NAMESPACE}.svc:9443", "127.0.0.1:8080", "localhost:8080"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(create_app(), host="127.0.0.1", port=int(os.environ.get("APP_PORT", "8080")))
