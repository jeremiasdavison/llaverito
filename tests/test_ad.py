from contextlib import ExitStack

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from conftest import ADMIN_EMAIL, ADMIN_PASSWORD, CSRF, Env, make_settings
from fake_ad import JWT_KEY, V2_KEY, FakeAd, make_jwt
from llaverito.app import create_app
from llaverito.config import ConfigError, Settings
from llaverito.models import User
from llaverito.security import UNUSABLE_HASH, hash_password, verify_password
from test_mcp import setup_http

ANA = "ana.perez@vicentelopez.gov.ar"
ANA_PW = "Ana-Clave-2026!"


@pytest.fixture
def ad():
    fake = FakeAd().start()
    fake.add(ANA, ANA_PW, "ANA MARIA PEREZ", groups=["app-llaverito-editores"])
    fake.add("boss@vicentelopez.gov.ar", "Boss-Clave-2026!", "JEFE DE AREA", groups=["app-llaverito-admin"])
    fake.add("pepe@vicentelopez.gov.ar", "Pepe-Clave-2026!", "JOSE GOMEZ", groups=["app-llaverito-lectores"])
    fake.add("intruso@vicentelopez.gov.ar", "Intruso-Clave-2026!", "SIN GRUPOS", groups=["otro-grupo"])
    yield fake
    fake.stop()


@pytest.fixture
def make_env(tmp_path, ad):
    stack = ExitStack()
    count = []

    def build(**over):
        count.append(1)
        workdir = tmp_path / f"env{len(count)}"
        workdir.mkdir()
        base = dict(
            ad_api_url=ad.url, ad_jwt_key=JWT_KEY.decode(), ad_allow_insecure=True,
            ad_v2_url=ad.url, ad_v2_api_key=V2_KEY, ad_v2_cache_seconds=0, allow_private_networks=True,
        )
        app = create_app(make_settings(workdir, **{**base, **over}))
        stack.enter_context(TestClient(app))
        env = Env(app)
        with env.rt.session() as s:
            s.add(User(email=ADMIN_EMAIL, name="Admin", password_hash=hash_password(ADMIN_PASSWORD), role="admin"))
        return env

    yield build
    stack.close()


def post_login(env, email, password):
    c = TestClient(env.app, base_url="http://testserver", headers=CSRF)
    return c, c.post("/api/auth/login", json={"email": email, "password": password})


def groups_cfg():
    return dict(
        ad_admin_groups="app-llaverito-admin",
        ad_editor_groups="app-llaverito-editores",
        ad_allowed_groups="app-llaverito-lectores",
    )


# ------------------------------------------------------------------ login básico


def test_ad_login_provisions_a_viewer_with_no_access(make_env):
    env = make_env()
    c, r = post_login(env, ANA, ANA_PW)
    assert r.status_code == 200, r.text
    me = r.json()
    assert me["auth_source"] == "ad" and me["role"] == "viewer" and me["name"] == "Ana Maria Perez"
    assert c.get("/api/folders").json() == []  # sin acceso a nada hasta que un admin lo conceda
    admin = env.login()
    assert any(u["email"] == ANA and u["auth_source"] == "ad" for u in admin.get("/api/users").json())


def test_wrong_password_unknown_user_and_empty_password_create_nothing(make_env, ad):
    env = make_env()
    assert post_login(env, ANA, "mal")[1].status_code == 401
    assert post_login(env, "nadie@vicentelopez.gov.ar", "x")[1].status_code == 401
    ad.calls.clear()
    assert post_login(env, ANA, "")[1].status_code == 401
    assert ad.calls == []  # contraseña vacía: ni se consulta a AD
    admin = env.login()
    assert [u["email"] for u in admin.get("/api/users").json()] == [ADMIN_EMAIL]


@pytest.mark.parametrize(
    "identity",
    ["34003991", "ana.perez", "ana.perez@evil.com", "ana*@vicentelopez.gov.ar", "ana)(cn=*@vicentelopez.gov.ar",
     "../ana@vicentelopez.gov.ar", "ana perez@vicentelopez.gov.ar", "a" * 200 + "@vicentelopez.gov.ar"],
)
def test_unsafe_identities_never_reach_ad(make_env, ad, identity):
    env = make_env()
    ad.calls.clear()
    assert post_login(env, identity, ANA_PW)[1].status_code == 401
    assert ad.calls == []  # en particular: un número (legajo) nunca llega a la API AD


def test_ad_accounts_have_no_local_password(make_env):
    assert verify_password(UNUSABLE_HASH, "") is False
    assert verify_password(UNUSABLE_HASH, UNUSABLE_HASH) is False
    env = make_env()
    assert post_login(env, ANA, ANA_PW)[1].status_code == 200
    with env.rt.session() as s:
        s.execute(text("UPDATE users SET auth_source='ad' WHERE email = :e"), {"e": ANA})
    assert post_login(env, ANA, "cualquier cosa larga")[1].status_code == 401


def test_local_account_with_same_email_is_not_taken_over(make_env):
    env = make_env()
    pw = env.add_user(ANA, "admin", "contraseña-local-larga")
    assert post_login(env, ANA, ANA_PW)[1].status_code == 401  # la clave de AD no entra a la cuenta local
    assert post_login(env, ANA, pw)[1].status_code == 200


# ------------------------------------------------------------------ respuestas falsas o rotas


def test_forged_or_broken_ad_responses_fail_closed(make_env, ad):
    env = make_env()
    ad.sign_key = b"otra-clave"
    r = post_login(env, ANA, ANA_PW)[1]
    assert r.status_code == 503  # firma inválida
    ad.sign_key = JWT_KEY
    ad.alg = "none"
    assert post_login(env, ANA, ANA_PW)[1].status_code == 503  # alg=none
    ad.alg = "HS256"
    ad.login_status = 500
    assert post_login(env, ANA, ANA_PW)[1].status_code == 503
    ad.login_status = 200
    ad.impersonate = "boss@vicentelopez.gov.ar"  # AD devuelve la identidad de otra persona
    assert post_login(env, ANA, ANA_PW)[1].status_code == 401
    admin = env.login()
    assert [u["email"] for u in admin.get("/api/users").json()] == [ADMIN_EMAIL]
    assert any(e["action"] == "login" and e["outcome"] == "error" for e in admin.get("/api/audit").json())


def test_https_is_required_and_v2_needs_a_key(tmp_path):
    with pytest.raises(ConfigError, match="https"):
        create_app(make_settings(tmp_path, ad_api_url="http://api-ad.vicentelopez.gov.ar"))
    with pytest.raises(ConfigError, match="API_KEY"):
        create_app(make_settings(tmp_path, ad_v2_url="https://apiadlopez.vicentelopez.gov.ar"))
    assert isinstance(Settings(_env_file=None), Settings)


# ------------------------------------------------------------------ grupos y roles


def test_groups_define_role_and_gate_access(make_env):
    env = make_env(**groups_cfg())
    assert post_login(env, "boss@vicentelopez.gov.ar", "Boss-Clave-2026!")[1].json()["role"] == "admin"
    assert post_login(env, ANA, ANA_PW)[1].json()["role"] == "editor"
    assert post_login(env, "pepe@vicentelopez.gov.ar", "Pepe-Clave-2026!")[1].json()["role"] == "viewer"
    r = post_login(env, "intruso@vicentelopez.gov.ar", "Intruso-Clave-2026!")[1]
    assert r.status_code == 403
    admin = env.login()
    assert "intruso@vicentelopez.gov.ar" not in [u["email"] for u in admin.get("/api/users").json()]


def test_group_lookup_failure_fails_closed(make_env, ad):
    env = make_env(**groups_cfg())
    ad.fail_groups = True
    assert post_login(env, ANA, ANA_PW)[1].status_code == 503


def test_role_follows_group_changes_and_kills_old_sessions(make_env, ad):
    env = make_env(**groups_cfg())
    c, r = post_login(env, ANA, ANA_PW)
    assert r.json()["role"] == "editor" and c.get("/api/auth/me").status_code == 200
    ad.users[ANA]["groups"] = ["app-llaverito-lectores"]
    c2, r2 = post_login(env, ANA, ANA_PW)
    assert r2.json()["role"] == "viewer"
    assert c.get("/api/auth/me").status_code == 401  # la sesión anterior tenía permisos de más
    assert c2.get("/api/auth/me").status_code == 200


def test_group_managed_roles_cannot_be_edited_by_hand(make_env):
    env = make_env(**groups_cfg())
    post_login(env, ANA, ANA_PW)
    admin = env.login()
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == ANA)
    assert admin.patch(f"/api/users/{uid}", json={"role": "admin"}).status_code == 409
    assert admin.patch(f"/api/users/{uid}", json={"password": "una contraseña larga!!"}).status_code == 422
    assert admin.patch(f"/api/users/{uid}", json={"active": False}).status_code == 200  # desactivar sí


# ------------------------------------------------------------------ baja de empleados (API AD v2)


def test_offboarded_employee_loses_session_and_agents(make_env, ad, echo_server):
    env = make_env(**groups_cfg())
    admin = env.login()
    folder = admin.post("/api/folders", json={"name": "infra"}).json()
    setup_http(admin, folder, echo_server)
    ana, _ = post_login(env, ANA, ANA_PW)
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == ANA)
    admin.put(f"/api/folders/{folder['id']}/access", json=[{"user_id": uid, "level": "write"}])
    token = ana.post("/api/agents", json={"name": "bot", "grants": [{"folder_id": folder["id"]}]}).json()["token"]
    args = {"credential": "cred://infra/api", "method": "GET", "url": f"{echo_server}/"}
    assert env.mcp(token, "http_request", args)["status_code"] == 200
    assert ana.get("/api/auth/me").status_code == 200

    ad.active.discard("ana.perez")  # RRHH la da de baja: la v2 deja de listarla
    assert ana.get("/api/auth/me").status_code == 401
    r = env.client.post("/mcp", headers={"Authorization": f"Bearer {token}"}, json={})
    assert r.status_code == 401
    assert post_login(env, ANA, ANA_PW)[1].status_code == 401  # AD acepta la clave, pero ya no es empleada activa


def test_v2_outage_uses_last_known_state_only_within_the_grace_window(make_env, ad):
    env = make_env()
    c, _ = post_login(env, ANA, ANA_PW)
    ad.v2_down = True
    assert c.get("/api/auth/me").status_code == 200  # dentro de la ventana de gracia
    strict = make_env(ad_v2_stale_seconds=0)
    c2, _ = post_login(strict, ANA, ANA_PW)
    assert c2.get("/api/auth/me").status_code == 401  # sin gracia, la v2 caída corta el acceso


# ------------------------------------------------------------------ operaciones sensibles


def test_reveal_for_ad_users_requires_the_ad_password(make_env, ad):
    env = make_env(**groups_cfg())
    admin = env.login()
    folder = admin.post("/api/folders", json={"name": "infra"}).json()
    ana, _ = post_login(env, ANA, ANA_PW)
    uid = next(u["id"] for u in admin.get("/api/users").json() if u["email"] == ANA)
    admin.put(f"/api/folders/{folder['id']}/access", json=[{"user_id": uid, "level": "write"}])
    r = ana.post("/api/credentials", json={"folder_id": folder["id"], "name": "tok", "type": "bearer_token",
                                           "meta": {"allowed_hosts": ["x.example.com"]}, "secret": {"secret": "valor-secreto-123"}})
    cid = r.json()["id"]
    assert ana.post(f"/api/credentials/{cid}/reveal", json={"password": "mal"}).status_code == 401
    ok = ana.post(f"/api/credentials/{cid}/reveal", json={"password": ANA_PW})
    assert ok.status_code == 200 and ok.json()["secret"]["secret"] == "valor-secreto-123"


def test_ad_passwords_never_reach_the_audit_log(make_env):
    env = make_env(**groups_cfg())
    post_login(env, ANA, ANA_PW)
    post_login(env, ANA, "intento-fallido-largo")
    with env.rt.session() as s:
        dump = repr(s.execute(text("SELECT * FROM audit_log")).fetchall())
    assert ANA_PW not in dump and "intento-fallido-largo" not in dump
