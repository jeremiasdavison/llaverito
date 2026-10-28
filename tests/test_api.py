import json

from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, CSRF

from fastapi.testclient import TestClient

SECRET = "sk-live-0123456789abcdef"


def new_cred(admin, folder, name="github", **over):
    body = {
        "folder_id": folder["id"],
        "name": name,
        "type": "bearer_token",
        "meta": {"allowed_hosts": ["api.github.com"], "description": "token de GitHub"},
        "secret": {"secret": SECRET},
        **over,
    }
    return admin.post("/api/credentials", json=body)


def test_requires_auth_and_csrf(env):
    anon = TestClient(env.app, base_url="http://testserver")
    assert anon.get("/api/credentials").status_code == 401
    r = anon.post("/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert r.status_code == 403  # sin cabecera anti-CSRF


def test_login_failures_are_throttled(env):
    c = TestClient(env.app, base_url="http://testserver", headers=CSRF)
    for _ in range(5):
        assert c.post("/api/auth/login", json={"email": "nadie@x.com", "password": "x"}).status_code == 401
    assert c.post("/api/auth/login", json={"email": "nadie@x.com", "password": "x"}).status_code == 429


def test_secret_never_listed_and_encrypted_at_rest(env, admin, folder):
    r = new_cred(admin, folder)
    assert r.status_code == 201, r.text
    assert SECRET not in r.text
    assert SECRET not in admin.get("/api/credentials").text
    assert SECRET not in admin.get(f"/api/credentials/{r.json()['id']}").text
    from sqlalchemy import text

    with env.rt.session() as s:
        blob = s.execute(text("SELECT blob FROM credentials")).scalar()
    assert SECRET.encode() not in blob


def test_reveal_needs_password_and_is_audited(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    assert admin.post(f"/api/credentials/{cid}/reveal", json={"password": "wrong password!!"}).status_code == 401
    r = admin.post(f"/api/credentials/{cid}/reveal", json={"password": ADMIN_PASSWORD})
    assert r.status_code == 200 and r.json()["secret"]["secret"] == SECRET
    actions = [(e["action"], e["outcome"]) for e in admin.get("/api/audit").json()]
    assert ("credential_reveal", "ok") in actions and ("credential_reveal", "denied") in actions
    assert SECRET not in json.dumps(admin.get("/api/audit").json())


def test_reveal_can_be_disabled_per_credential(admin, folder):
    cid = new_cred(admin, folder, allow_reveal=False).json()["id"]
    r = admin.post(f"/api/credentials/{cid}/reveal", json={"password": ADMIN_PASSWORD})
    assert r.status_code == 403


def test_roles_and_folder_acl(env, admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    other = admin.post("/api/folders", json={"name": "privado"}).json()
    new_cred(admin, other, name="oculta")
    pw = env.add_user("lector@x.gov.ar", "viewer")
    viewer = env.login("lector@x.gov.ar", pw)
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == "lector@x.gov.ar")

    assert viewer.get("/api/credentials").json() == []  # sin acceso a ninguna carpeta
    assert viewer.get(f"/api/credentials/{cid}").status_code == 404
    admin.put(f"/api/folders/{folder['id']}/access", json=[{"user_id": uid, "level": "write"}])

    listed = viewer.get("/api/credentials").json()
    assert [c["name"] for c in listed] == ["github"]  # "privado" sigue oculta
    assert listed[0]["can_write"] is False  # viewer nunca escribe, aunque el ACL diga write
    assert viewer.patch(f"/api/credentials/{cid}", json={"sensitive": True}).status_code == 403
    assert viewer.post(f"/api/credentials/{cid}/reveal", json={"password": pw}).status_code == 403
    assert viewer.get("/api/users").status_code == 403
    assert viewer.get("/api/audit").status_code == 403
    assert viewer.post("/api/agents", json={"name": "x"}).status_code == 403


def test_editor_cannot_grant_what_they_cannot_see(env, admin, folder):
    new_cred(admin, folder)
    pw = env.add_user("editor@x.gov.ar", "editor")
    editor = env.login("editor@x.gov.ar", pw)
    r = editor.post("/api/agents", json={"name": "bot", "grants": [{"folder_id": folder["id"]}]})
    assert r.status_code == 403


def test_agent_token_shown_once_and_revocation(admin, folder):
    r = admin.post("/api/agents", json={"name": "bot", "grants": [{"folder_id": folder["id"]}]})
    assert r.status_code == 201
    token = r.json()["token"]
    assert token.startswith("llv_")
    listed = admin.get("/api/agents").json()
    assert "token" not in listed[0] and token not in json.dumps(listed)
    assert admin.delete(f"/api/agents/{r.json()['id']}").status_code == 204
    assert admin.get("/api/agents").json()[0]["revoked"] is True


def test_validation_errors(admin, folder):
    assert new_cred(admin, folder, secret={"secret": "abc"}).status_code == 422
    assert new_cred(admin, folder, type="nope").status_code == 422
    assert new_cred(admin, folder, name="a/b").status_code == 422
    assert new_cred(admin, folder).status_code == 201
    assert new_cred(admin, folder).status_code == 422  # duplicada


def test_rotation_changes_secret_and_bumps_version(admin, folder):
    cid = new_cred(admin, folder).json()["id"]
    r = admin.patch(f"/api/credentials/{cid}", json={"secret": {"secret": "sk-rotated-9876543210"}})
    assert r.json()["version"] == 2
    got = admin.post(f"/api/credentials/{cid}/reveal", json={"password": ADMIN_PASSWORD}).json()
    assert got["secret"]["secret"] == "sk-rotated-9876543210"


def test_password_change_invalidates_session(env, admin):
    pw = env.add_user("u@x.gov.ar", "editor")
    c = env.login("u@x.gov.ar", pw)
    assert c.get("/api/auth/me").status_code == 200
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == "u@x.gov.ar")
    admin.patch(f"/api/users/{uid}", json={"password": "una contraseña nueva larga"})
    assert c.get("/api/auth/me").status_code == 401
