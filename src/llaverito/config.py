import base64
from functools import lru_cache
from pathlib import Path

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ConfigError(RuntimeError):
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LLAVERITO_", env_file=".env", extra="ignore")

    database_url: str = "sqlite:///./llaverito.db"

    # Clave maestra (KEK): 32 bytes en base64. Alternativamente, ruta a un archivo que la contenga.
    master_key: SecretStr | None = None
    master_key_file: Path | None = None

    session_ttl_minutes: int = 480
    cookie_secure: bool = False

    # Solo para desarrollo/tests: permite que el broker HTTP llegue a loopback/link-local.
    allow_private_networks: bool = False

    http_timeout_seconds: float = 30.0
    http_max_response_bytes: int = 1_000_000
    ssh_default_timeout: int = 60
    ssh_max_timeout: int = 300
    ssh_max_output_bytes: int = 1_000_000

    # --- Login con Active Directory vía API AD (v1: POST /login y /gruposUser) ---
    ad_api_url: str = ""  # ej. https://api-ad.vicentelopez.gov.ar ; vacío = login AD deshabilitado
    ad_jwt_key: SecretStr | None = None  # clave HS256 con la que la API AD firma sus respuestas (opcional)
    ad_ca_file: Path | None = None  # CA municipal si el certificado no es de una CA pública
    ad_email_domain: str = "vicentelopez.gov.ar"
    ad_allow_insecure: bool = False  # solo desarrollo: permite http://
    ad_timeout_seconds: float = 10.0
    ad_default_role: str = "viewer"
    # Grupos de AD (nombres separados por coma). Si hay admin/editor, el rol de las cuentas AD sale de los grupos.
    ad_admin_groups: str = ""
    ad_editor_groups: str = ""
    ad_allowed_groups: str = ""  # si se define, solo entran miembros de estos grupos (o de los de admin/editor)

    # --- API AD v2: confirma que la cuenta sigue activa (da de baja sesiones y agentes de quien se fue) ---
    ad_v2_url: str = ""  # ej. https://apiadlopez.vicentelopez.gov.ar
    ad_v2_api_key: SecretStr | None = None
    ad_v2_cache_seconds: int = 300
    ad_v2_stale_seconds: int = 86400  # cuánto se tolera que la v2 no responda usando el último dato conocido

    approval_ttl_seconds: int = 600
    agent_rate_limit_per_minute: int = 60

    # Hosts adicionales aceptados en la cabecera Host del endpoint MCP (separados por coma).
    public_hosts: str = ""

    def load_kek(self) -> bytes:
        raw: str | None = None
        if self.master_key is not None:
            raw = self.master_key.get_secret_value()
        elif self.master_key_file is not None:
            raw = Path(self.master_key_file).read_text(encoding="utf-8").strip()
        if not raw:
            raise ConfigError(
                "Falta la clave maestra. Generá una con `llaverito gen-key` y definí "
                "LLAVERITO_MASTER_KEY o LLAVERITO_MASTER_KEY_FILE."
            )
        try:
            key = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))
        except Exception as exc:
            raise ConfigError("La clave maestra no es base64 válido.") from exc
        if len(key) != 32:
            raise ConfigError("La clave maestra debe tener exactamente 32 bytes.")
        return key

    @staticmethod
    def _names(raw: str) -> set[str]:
        return {x.strip().lower() for x in raw.split(",") if x.strip()}

    @property
    def admin_groups(self) -> set[str]:
        return self._names(self.ad_admin_groups)

    @property
    def editor_groups(self) -> set[str]:
        return self._names(self.ad_editor_groups)

    @property
    def login_groups(self) -> set[str]:
        return self._names(self.ad_allowed_groups) | self.admin_groups | self.editor_groups

    def validate_ad(self) -> None:
        for name, url in (("LLAVERITO_AD_API_URL", self.ad_api_url), ("LLAVERITO_AD_V2_URL", self.ad_v2_url)):
            if url and not url.startswith("https://") and not self.ad_allow_insecure:
                raise ConfigError(f"{name} debe usar https:// (las contraseñas viajan por ahí).")
        if self.ad_v2_url and not self.ad_v2_api_key:
            raise ConfigError("Falta LLAVERITO_AD_V2_API_KEY para usar la API AD v2.")
        if self.ad_default_role not in ("viewer", "editor"):
            raise ConfigError("LLAVERITO_AD_DEFAULT_ROLE debe ser viewer o editor.")

    def mcp_allowed_hosts(self) -> list[str]:
        hosts = ["localhost:*", "127.0.0.1:*", "[::1]:*"]
        for h in self.public_hosts.split(","):
            h = h.strip()
            if h:
                hosts.append(h)
        return hosts


@lru_cache
def get_settings() -> Settings:
    return Settings()
