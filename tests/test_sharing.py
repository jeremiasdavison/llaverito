"""Compartir credenciales con personas, por poco tiempo o de forma permanente."""

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select, update

from llaverito.models import CredentialShare, User
from test_api import SECRET, new_cred
from test_mcp import setup_http

PW = "una contraseña larga!!"


def uid(admin, email):
    return next(u["id"] for u in admin.get("/api/users").json() if u["email"] == email)


def person(env, admin, email, role):
    pw = env.add_user(email, role, PW)
    return env.login(email, pw), uid(admin, email)


def share(client, cid, user_id, **body):
    return client.post(f"/api/credentials/{cid}/shares", json={"user_id": user_id, **body})


def expire_now(env, minutes=1):
    with env.rt.session() as s:
        s.execute(update(CredentialShare).values(expires_at=datetime.now(UTC) - timedelta(minutes=minutes)))


# ------------------------------------------------------------------ permanente


def test_permanent_share_gives_reveal_without_folder_access(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    new_cred(admin, folder, name="otra")
    viewer, vid = person(env, admin, "lector@x.gov.ar", "viewer")
    assert viewer.get("/api/credentials").json() == []

    r = share(admin, cid, vid, level="reveal")
    assert r.status_code == 201 and r.json()["permanent"] is True and r.json()["expires_at"] is None

    items = viewer.get("/api/credentials").json()
    assert [c["name"] for c in items] == ["github"]  # solo la compartida, no el resto de la carpeta
    c = items[0]
    assert c["access"] == "shared" and c["shared_permanent"] is True and c["can_write"] is False
    assert [x["name"] for x in viewer.get("/api/credentials?shared=true").json()] == ["github"]
    assert viewer.get("/api/folders").json() == []  # ve la credencial, no la carpeta

    got = viewer.post(f"/api/credentials/{cid}/reveal", json={"password": PW})
    assert got.status_code == 200 and got.json()["secret"]["secret"] == SECRET

    # lo compartido no da poder de edición ni de re-compartir
    assert viewer.patch(f"/api/credentials/{cid}", json={"sensitive": True}).status_code == 403
    assert viewer.delete(f"/api/credentials/{cid}").status_code == 403
    assert viewer.get(f"/api/credentials/{cid}/shares").status_code == 403
    assert viewer.get("/api/users/directory").status_code == 403
    assert share(viewer, cid, vid, level="reveal").status_code == 403


def test_use_level_cannot_reveal_and_reveal_can_be_blocked_per_credential(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    blocked = new_cred(admin, folder, name="sin-reveal", allow_reveal=False).json()["id"]
    editor, eid = person(env, admin, "ed@x.gov.ar", "editor")
    assert share(admin, cid, eid, level="use").status_code == 201
    assert editor.post(f"/api/credentials/{cid}/reveal", json={"password": PW}).status_code == 403
    assert share(admin, blocked, eid, level="reveal").status_code == 201
    assert editor.post(f"/api/credentials/{blocked}/reveal", json={"password": PW}).status_code == 403


# ------------------------------------------------------------------ temporal


def test_temporary_share_expires_by_itself(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    viewer, vid = person(env, admin, "lector@x.gov.ar", "viewer")
    r = share(admin, cid, vid, level="reveal", expires_in_minutes=15)
    assert r.status_code == 201 and r.json()["permanent"] is False
    left = datetime.fromisoformat(r.json()["expires_at"]) - datetime.now(UTC)
    assert timedelta(minutes=14) < left <= timedelta(minutes=15)
    assert viewer.post(f"/api/credentials/{cid}/reveal", json={"password": PW}).status_code == 200

    expire_now(env)  # pasa el tiempo
    assert viewer.get("/api/credentials").json() == []
    assert viewer.get(f"/api/credentials/{cid}").status_code == 404
    assert viewer.post(f"/api/credentials/{cid}/reveal", json={"password": PW}).status_code == 404
    listed = admin.get(f"/api/credentials/{cid}/shares").json()
    assert listed[0]["expired"] is True  # queda el historial para el dueño

    again = share(admin, cid, vid, level="reveal", expires_in_minutes=60)  # volver a compartir renueva
    assert again.status_code == 201 and again.json()["id"] == listed[0]["id"]
    assert [c["name"] for c in viewer.get("/api/credentials").json()] == ["github"]


def test_changing_a_temporary_share_to_permanent_and_revoking(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    viewer, vid = person(env, admin, "lector@x.gov.ar", "viewer")
    sid = share(admin, cid, vid, level="reveal", expires_in_minutes=5).json()["id"]
    assert share(admin, cid, vid, level="reveal").json()["permanent"] is True
    assert len(viewer.get("/api/credentials").json()) == 1  # ya no tiene vencimiento
    assert admin.delete(f"/api/credentials/{cid}/shares/{sid}").status_code == 204
    assert viewer.get("/api/credentials").json() == []
    assert admin.delete(f"/api/credentials/{cid}/shares/{sid}").status_code == 404


# ------------------------------------------------------------------ agentes y aprobaciones


def test_use_share_lets_an_editor_run_agents_until_revoked_or_expired(env, admin, folder, echo_server):
    cid = setup_http(admin, folder, echo_server)["id"]
    editor, eid = person(env, admin, "ed@x.gov.ar", "editor")
    args = {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}
    assert editor.post("/api/agents", json={"name": "bot", "grants": [{"credential_id": cid}]}).status_code == 403  # sin compartir

    sid = share(admin, cid, eid, level="use").json()["id"]
    token = editor.post("/api/agents", json={"name": "bot", "grants": [{"credential_id": cid}]}).json()["token"]
    assert env.mcp(token, "http_request", args)["status_code"] == 200

    admin.delete(f"/api/credentials/{cid}/shares/{sid}")
    assert "no encontrada o sin acceso" in env.mcp(token, "http_request", args, expect_error=True)

    share(admin, cid, eid, level="use", expires_in_minutes=15)
    assert env.mcp(token, "http_request", args)["status_code"] == 200
    expire_now(env)
    assert "no encontrada o sin acceso" in env.mcp(token, "http_request", args, expect_error=True)
    items = env.mcp(token, "list_credentials")
    assert (items["result"] if isinstance(items, dict) else items) == []


def test_approvals_follow_the_share(env, admin, folder, echo_server):
    cid = setup_http(admin, folder, echo_server, sensitive=True)["id"]
    editor, eid = person(env, admin, "ed@x.gov.ar", "editor")
    share(admin, cid, eid, level="use")
    token = editor.post("/api/agents", json={"name": "bot", "grants": [{"credential_id": cid}]}).json()["token"]
    args = {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}
    aid = env.mcp(token, "http_request", args)["approval_id"]
    assert editor.get("/api/approvals?status=pending").json()[0]["id"] == aid  # su dueño la ve

    sid = admin.get(f"/api/credentials/{cid}/shares").json()[0]["id"]
    admin.delete(f"/api/credentials/{cid}/shares/{sid}")
    assert editor.post(f"/api/approvals/{aid}/decide", json={"approve": True}).status_code == 404
    assert admin.post(f"/api/approvals/{aid}/decide", json={"approve": True}).status_code == 200


# ------------------------------------------------------------------ validaciones y auditoría


def test_share_validations(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    me = admin.get("/api/auth/me").json()["id"]
    viewer, vid = person(env, admin, "lector@x.gov.ar", "viewer")
    editor, eid = person(env, admin, "ed@x.gov.ar", "editor")
    other, oid = person(env, admin, "otro@x.gov.ar", "editor")

    assert share(admin, cid, me).status_code == 422  # consigo mismo
    assert share(admin, cid, "no-existe").status_code == 404
    assert share(admin, cid, vid, level="use").status_code == 422  # un lector no puede tener agentes
    assert share(admin, cid, eid, expires_in_minutes=4).status_code == 422  # mínimo 5 minutos
    assert share(admin, cid, eid, expires_in_minutes=525601).status_code == 422  # máximo 1 año
    assert share(admin, cid, eid, level="admin").status_code == 422

    admin.put(f"/api/folders/{folder['id']}/access", json=[{"user_id": eid, "level": "write"}, {"user_id": oid, "level": "read"}])
    assert share(admin, cid, eid).status_code == 409  # ya tiene la carpeta
    assert share(other, cid, vid, level="reveal").status_code == 403  # solo lectura en la carpeta: no puede compartir
    assert share(editor, cid, vid, level="reveal").status_code == 201  # escritura: sí

    admin.patch(f"/api/users/{vid}", json={"active": False})
    assert share(admin, cid, vid, level="reveal").status_code == 404  # inactiva


def test_directory_lists_only_what_is_needed(env, admin):
    editor, eid = person(env, admin, "ed@x.gov.ar", "editor")
    rows = editor.get("/api/users/directory").json()
    assert eid not in [r["id"] for r in rows]
    assert {k for r in rows for k in r} <= {"id", "name", "email", "role", "department"}
    assert "hash" not in json.dumps(rows).lower()


def test_audit_records_sharing_and_reveal_via_share(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    viewer, vid = person(env, admin, "lector@x.gov.ar", "viewer")
    sid = share(admin, cid, vid, level="reveal", expires_in_minutes=60).json()["id"]
    viewer.post(f"/api/credentials/{cid}/reveal", json={"password": PW})
    admin.delete(f"/api/credentials/{cid}/shares/{sid}")
    entries = admin.get("/api/audit").json()
    actions = [e["action"] for e in entries]
    assert {"credential_share", "credential_reveal", "credential_unshare"} <= set(actions)
    shared = next(e for e in entries if e["action"] == "credential_share")
    assert shared["target"] == "lector@x.gov.ar" and shared["detail"]["permanent"] is False
    assert next(e for e in entries if e["action"] == "credential_reveal")["detail"]["via"] == "share"
    assert SECRET not in json.dumps(entries)


def test_deleting_a_credential_removes_its_shares(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    _, vid = person(env, admin, "lector@x.gov.ar", "viewer")
    share(admin, cid, vid, level="reveal")
    assert admin.delete(f"/api/credentials/{cid}").status_code == 204
    with env.rt.session() as s:
        assert s.scalars(select(CredentialShare)).all() == []
        assert s.scalar(select(User.id).where(User.email == "lector@x.gov.ar"))
