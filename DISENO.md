# Llaverito — Diseño inicial

Bóveda de credenciales de la Municipalidad (API keys, SSH, accesos) con dos puertas de entrada:

1. **Web UI** — para personas: ver, crear, compartir y (con auditoría) revelar credenciales; terminal SSH en el navegador.
2. **MCP server** — para agentes: usan credenciales **sin verlas** (modelo "brokered").

## Principio central: el agente usa, no lee

Ninguna tool MCP devuelve el valor de un secreto. El agente pasa una **referencia** (`cred://infra/prod-db-ssh`) y una **acción**; Llaverito ejecuta la acción con el secreto inyectado del lado servidor y devuelve solo el resultado, con el secreto redactado.

| Tool MCP | Qué hace | El agente ve |
|---|---|---|
| `list_credentials` | Lista metadatos (nombre, tipo, tags, hosts permitidos) | Sin valores |
| `http_request` | Proxy HTTP: Llaverito agrega `Authorization`/API key/Basic | Status + body (redactado) |
| `ssh_exec` | Ejecuta un comando por SSH con la clave guardada | stdout/stderr (redactado) |
| `run_with_env` | Corre un comando en un runner con secretos como variables de entorno (estilo `op run`) | Salida redactada |
| `request_access` | Pide aprobación humana para una acción sensible | Estado del pedido |
| *(fase 4)* `browser_login` | Rellena un login en un navegador controlado (Playwright) | Solo "login ok/fallo" |

## Patrones tomados de la documentación pública de 1Password

Fuentes: 1password.dev (Secure AI access, Security for AI). Solo comportamiento documentado, no código.

| Patrón de 1Password | Equivalente en Llaverito |
|---|---|
| **Referencias de secretos** + `op run` (inyecta variables en un proceso, nada en disco) | CLI `llaverito run --env <entorno> -- cmd`; `mcp.json` sin tokens, solo referencias |
| **Placeholders + gateway** (OpenShell): el agente trabaja con marcadores y el gateway, fuera del sandbox, los sustituye solo en hosts aprobados | Proxy `http_request`: el agente manda `{{cred://x}}`, el broker sustituye si el host está en la allowlist |
| **Custodia con caducidad**: el acceso vence aunque el sandbox siga vivo | Grants con TTL por agente/credencial |
| **Autorización por acción** (prompt de aprobación / biometría) | Cola de aprobaciones (web/push) para credenciales sensibles |
| **MCP que nunca devuelve secretos** | Regla de diseño de todas las tools: cero valores en respuestas |
| **Hooks que validan el entorno** antes de que el agente ejecute shell | Plugin/hook de Claude Code que verifica que no haya secretos en claro (`.env`, `mcp.json`) |
| **Shell plugins**: CLIs autenticadas desde la app, sin keys en el perfil | Helper local que entrega tokens efímeros a CLIs |

## Controles de seguridad (lo que realmente protege)

- **Identidad por agente**: token propio por agente/usuario, con alcance (scopes) a carpetas/credenciales concretas.
- **Allowlist de destino por credencial**: una API key de X solo puede usarse contra `api.x.com`. Evita que una inyección de prompt mande la clave a un host atacante. Bloquear SSRF (IPs internas/metadata) salvo permiso explícito.
- **Allowlist de comandos SSH** (o aprobación humana para los que no estén en lista).
- **Redacción de salida**: reemplazar el secreto y sus variantes (base64, URL-encoded, hex) antes de devolver al agente. Es mitigación, no garantía → por eso importa la allowlist.
- **Aprobación humana** (push/web) para credenciales marcadas como sensibles.
- **Auditoría inmutable**: quién (usuario/agente), qué credencial, qué acción, destino, resultado, hora. Nunca se loguea el valor.
- **Rate limiting** y expiración de grants.

## Criptografía

- **Envelope encryption**: cada secreto con su DEK (AES-256-GCM); las DEK se cifran con una KEK maestra.
- KEK: sellada con **unseal Shamir** al arrancar, o desde un KMS/HSM si hay uno disponible.
- Trade-off consciente: el cifrado extremo a extremo estilo 1Password es incompatible con ejecutar acciones del lado servidor. Aquí el servidor puede descifrar en memoria, así que el servidor es el activo crítico a proteger (red interna, hardening, backups cifrados).

## Arquitectura

```
 Navegador (React) ──HTTPS──┐
                            ├─► API (FastAPI) ─► PostgreSQL (secretos cifrados + auditoría)
 Agentes (MCP clients) ─────┤        │
   (Streamable HTTP + token)│        ├─► Broker: http proxy / ssh (asyncssh) / runner
                            │        └─► Cola de aprobaciones
 Terminal web (xterm.js) ───┘ WebSocket → gateway SSH (clave nunca llega al navegador)
```

- **Auth de personas**: SSO institucional (OIDC / LDAP / AD) + MFA; roles (admin, editor, lector) y carpetas compartidas.
- **Stack propuesto**: Python 3.12 + FastAPI, SDK oficial de MCP, asyncssh, PostgreSQL, React + Vite, Docker Compose on-prem. (Encaja con tu stack habitual; si la Municipalidad prefiere Node/TS, el diseño no cambia.)

## "Tipo Tabby"

Tabby = terminal con perfiles SSH, sincronizados. En Llaverito: los perfiles SSH son credenciales de la bóveda, y la terminal web (xterm.js sobre WebSocket) abre la sesión desde el servidor. Opcional más adelante: exponer un puente local para que Tabby de escritorio lea perfiles.

## Fases

1. **Bóveda + UI + auditoría**: CRUD, carpetas, roles, cifrado, SSO, log de auditoría.
2. **MCP brokered**: `list_credentials`, `http_request`, `ssh_exec`, tokens de agente, allowlists, redacción.
3. **Terminal SSH web + aprobaciones humanas + rotación/expiración**.
4. **Browser login** (Playwright), `run_with_env`, importadores (1Password CSV, Bitwarden).

## Evaluar antes de construir

Hay proyectos open source que cubren partes (HashiCorp Vault / **OpenBao** para secretos, **Infisical**, **Vaultwarden** como bóveda de personas). Vale la pena decidir si Llaverito construye todo o si es una capa fina (UI + broker MCP) sobre uno de ellos. Construir todo da control total, pero criptografía y gestión de claves propias son el mayor riesgo del proyecto.

## Preguntas abiertas

- ¿Cuántos usuarios/agentes y qué SSO usa la Municipalidad (AD, Azure AD, Keycloak)?
- ¿Dónde correrá (servidor on-prem, VM, Docker) y hay HSM/KMS?
- ¿Los agentes serán Claude Code / Claude Desktop (MCP remoto) u otros?
- ¿Construir desde cero u opcionalmente sobre OpenBao/Infisical?
