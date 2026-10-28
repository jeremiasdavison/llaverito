"""Pruebas adversariales: lo que intentaría un atacante o un agente comprometido."""

import time

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from conftest import ADMIN_PASSWORD, CSRF
from test_api import SECRET, new_cred
from test_mcp import new_agent, setup_http


def client_with_cookie(env, token):
    c = TestClient(env.app, base_url="http://testserver", headers=CSRF)
    c.cookies.set("llv_session", token)
    return c


def listed(result):
    return result["result"] if isinstance(result, dict) else result


def user_id(admin, email):
    return next(u["id"] for u in admin.get("/api/users").json() if u["email"] == email)


# ------------------------------------------------------------------ sesiones


def test_forged_and_expired_session_tokens_are_rejected(env, admin):
    uid = admin.get("/api/auth/me").json()["id"]
    now = int(time.time())
    claims = {"sub": uid, "sv": 1, "iat": now, "exp": now + 3600}
    bad = [
        jwt.encode(claims, "otra-clave-otra-clave-otra-clave-32", algorithm="HS256"),
        jwt.encode(claims, key="", algorithm="none"),
        jwt.encode({**claims, "exp": now - 10}, env.rt.jwt_secret, algorithm="HS256"),
        jwt.encode({**claims, "sv": 99}, env.rt.jwt_secret, algorithm="HS256"),
    ]
    for token in bad:
        assert client_with_cookie(env, token).get("/api/auth/me").status_code == 401
    good = jwt.encode(claims, env.rt.jwt_secret, algorithm="HS256")
    assert client_with_cookie(env, good).get("/api/auth/me").status_code == 200  # control


def test_logout_revokes_the_token_on_the_server(env):
    c = env.login()
    stolen = c.cookies.get("llv_session")
    assert client_with_cookie(env, stolen).get("/api/auth/me").status_code == 200
    c.post("/api/auth/logout")
    assert client_with_cookie(env, stolen).get("/api/auth/me").status_code == 401


def test_lockout_holds_even_with_the_right_password(env):
    pw = env.add_user("victima@x.gov.ar", "editor")
    c = TestClient(env.app, base_url="http://testserver", headers=CSRF)
    for _ in range(5):
        assert c.post("/api/auth/login", json={"email": "victima@x.gov.ar", "password": "mal"}).status_code == 401
    assert c.post("/api/auth/login", json={"email": "victima@x.gov.ar", "password": pw}).status_code == 429


def test_reveal_brute_force_is_throttled(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    for _ in range(5):
        assert admin.post(f"/api/credentials/{cid}/reveal", json={"password": "incorrecta!!"}).status_code == 401
    assert admin.post(f"/api/credentials/{cid}/reveal", json={"password": ADMIN_PASSWORD}).status_code == 429


def test_security_headers_and_no_public_schema(env):
    r = env.client.get("/")
    assert "script-src 'self'" in r.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert env.client.get("/api/docs").status_code == 404
    assert env.client.get("/api/openapi.json").status_code == 404
    assert env.client.get("/api/credentials").headers["cache-control"] == "no-store"


# ------------------------------------------------------------------ cifrado e integridad


def test_tampered_ciphertext_fails_closed(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    cid = admin.get("/api/credentials").json()[0]["id"]
    with env.rt.session() as s:
        s.execute(text("UPDATE credentials SET blob = :b"), {"b": b"\x00" * 60})
    r = admin.post(f"/api/credentials/{cid}/reveal", json={"password": ADMIN_PASSWORD})
    assert r.status_code == 500 and "integridad" in r.text and SECRET not in r.text
    err = env.mcp(token, "http_request", {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}, expect_error=True)
    assert "integridad" in err and SECRET not in err


def test_ciphertext_cannot_be_moved_between_credentials(env, admin, folder):
    a = new_cred(admin, folder, name="a").json()["id"]
    b = new_cred(admin, folder, name="b", secret={"secret": "otro-secreto-123456"}).json()["id"]
    with env.rt.session() as s:
        blob, dek = s.execute(text("SELECT blob, wrapped_dek FROM credentials WHERE id = :i"), {"i": a}).one()
        s.execute(text("UPDATE credentials SET blob = :b, wrapped_dek = :d WHERE id = :i"), {"b": blob, "d": dek, "i": b})
    r = admin.post(f"/api/credentials/{b}/reveal", json={"password": ADMIN_PASSWORD})
    assert r.status_code == 500 and SECRET not in r.text


# ------------------------------------------------------------------ privilegios vigentes


def editor_with_agent(env, admin, folder, email="ed@x.gov.ar"):
    pw = env.add_user(email, "editor")
    editor = env.login(email, pw)
    uid = user_id(admin, email)
    access = f"/api/folders/{folder['id']}/access"
    admin.put(access, json=[{"user_id": uid, "level": "write"}])
    token = editor.post("/api/agents", json={"name": "bot", "grants": [{"folder_id": folder["id"]}]}).json()["token"]
    return editor, uid, token, access


def test_agent_access_follows_its_owner_access(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    editor, uid, token, access = editor_with_agent(env, admin, folder)
    args = {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}
    assert env.mcp(token, "http_request", args)["status_code"] == 200
    assert len(listed(env.mcp(token, "list_credentials"))) == 1

    admin.put(access, json=[])  # el dueño pierde la carpeta: el agente también
    assert "no encontrada o sin acceso" in env.mcp(token, "http_request", args, expect_error=True)
    assert listed(env.mcp(token, "list_credentials")) == []

    admin.put(access, json=[{"user_id": uid, "level": "read"}])
    assert env.mcp(token, "http_request", args)["status_code"] == 200  # recupera el acceso


@pytest.mark.parametrize("change", [{"active": False}, {"role": "viewer"}])
def test_agent_is_cut_off_when_owner_is_disabled_or_demoted(env, admin, folder, echo_server, change):
    setup_http(admin, folder, echo_server)
    _, uid, token, _ = editor_with_agent(env, admin, folder)
    assert admin.patch(f"/api/users/{uid}", json=change).status_code == 200
    r = env.client.post("/mcp", headers={"Authorization": f"Bearer {token}"}, json={})
    assert r.status_code == 401


def test_approver_must_still_see_the_folder(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server, sensitive=True)
    editor, uid, token, access = editor_with_agent(env, admin, folder)
    args = {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}
    aid = env.mcp(token, "http_request", args)["approval_id"]
    admin.put(access, json=[])
    assert editor.post(f"/api/approvals/{aid}/decide", json={"approve": True}).status_code == 404
    assert admin.post(f"/api/approvals/{aid}/decide", json={"approve": True}).status_code == 200


def test_other_users_cannot_decide_or_see_foreign_approvals(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server, sensitive=True)
    _, _, token, _ = editor_with_agent(env, admin, folder)
    aid = env.mcp(token, "http_request", {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"})["approval_id"]
    pw = env.add_user("otro@x.gov.ar", "editor")
    other = env.login("otro@x.gov.ar", pw)
    assert other.get("/api/approvals").json() == []
    assert other.post(f"/api/approvals/{aid}/decide", json={"approve": True}).status_code == 404


# ------------------------------------------------------------------ agente hostil


def test_crlf_header_injection_and_bad_header_names(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    base = {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}
    err = env.mcp(token, "http_request", {**base, "headers": {"X-A": "ok\r\nX-Injected: 1"}}, expect_error=True)
    assert "Falló la solicitud" in err  # h11 rechaza la cabecera: nunca llega al servidor
    err = env.mcp(token, "http_request", {**base, "headers": {"Bad Name": "x"}}, expect_error=True)
    assert "inválido" in err
    for forbidden in ("Host", "Content-Length", "Transfer-Encoding"):
        assert "no permitida" in env.mcp(token, "http_request", {**base, "headers": {forbidden: "x"}}, expect_error=True)


@pytest.mark.parametrize("ref", ["cred://../../etc/passwd", "cred://x/'; DROP TABLE credentials;--", "", "cred://", "a" * 5000, "%00"])
def test_hostile_references_are_just_not_found(env, admin, folder, echo_server, ref):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    err = env.mcp(token, "http_request", {"credential": ref, "method": "GET", "url": f"{echo_server}/"}, expect_error=True)
    assert "no encontrada o sin acceso" in err
    assert admin.get("/api/audit/verify").json()["ok"] is True  # la tabla sigue intacta


def test_agent_cannot_exfiltrate_secret_to_the_response_by_encoding(env, admin, folder, echo_server):
    """El servidor eco devuelve el cuerpo tal cual: probamos variantes comunes de ofuscación."""
    import base64

    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    b64 = base64.b64encode(SECRET.encode()).decode()
    out = env.mcp(
        token,
        "http_request",
        {
            "credential": "cred://infra/api",
            "method": "POST",
            "url": f"{echo_server}/x",
            "body": "{{secret}} " + b64 + " {{secret}}",
            "headers": {"X-Hex": "{{secret}}"},
        },
    )
    blob = str(out)
    assert SECRET not in blob and b64 not in blob


def test_audit_never_contains_secret_or_token(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    env.mcp(token, "http_request", {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/?k={{{{secret}}}}"})
    with env.rt.session() as s:
        rows = s.execute(text("SELECT * FROM audit_log")).fetchall()
    dump = repr(rows)
    assert SECRET not in dump and token not in dump
