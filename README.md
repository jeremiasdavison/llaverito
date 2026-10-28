# Llaverito

Bóveda de credenciales de la Municipalidad (API keys, accesos SSH, contraseñas) con dos puertas:

- **Web UI** para personas: carpetas, roles, revelar con reconfirmación de contraseña, aprobaciones, auditoría.
- **Servidor MCP** para agentes: **usan las credenciales sin verlas**. El agente referencia `cred://carpeta/nombre`
  y Llaverito ejecuta la acción del lado servidor, inyectando la autenticación y redactando la salida.

Diseño y decisiones: [DISENO.md](DISENO.md). Este repo implementa las fases 1 y 2.

## Inicio rápido (desarrollo)

Requiere Python 3.12+ y [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run llaverito gen-key > master.key          # clave maestra (KEK): guardala fuera del repo y con backup
export LLAVERITO_MASTER_KEY_FILE=./master.key
uv run llaverito create-admin --email vos@vicentelopez.gov.ar
uv run llaverito serve                          # http://127.0.0.1:8000
```

Tests: `uv run pytest` (100 tests: cifrado, API, broker HTTP, SSH real contra un servidor en proceso, aprobaciones, auditoría, login AD contra una API AD simulada, compartir credenciales con vencimiento y pruebas adversariales de seguridad).

> En Windows, si el entorno virtual queda en una ruta larga (>260 caracteres) los módulos compilados no cargan.
> Usá una ruta corta: `UV_PROJECT_ENVIRONMENT=C:\venvs\llaverito`.

## Producción

```bash
cp .env.example .env            # completar
uv run llaverito gen-key > master.key
docker compose up -d --build
docker compose exec app llaverito create-admin --email vos@vicentelopez.gov.ar
```

Publicar **detrás de un proxy con TLS** (el compose solo escucha en 127.0.0.1). Definir
`LLAVERITO_PUBLIC_HOSTS` con el dominio público (el endpoint MCP valida la cabecera Host).

Variables principales (`LLAVERITO_*`): `DATABASE_URL`, `MASTER_KEY` / `MASTER_KEY_FILE`, `COOKIE_SECURE`,
`APPROVAL_TTL_SECONDS`, `AGENT_RATE_LIMIT_PER_MINUTE`, `HTTP_MAX_RESPONSE_BYTES`, `SSH_MAX_TIMEOUT`.

## Login con Active Directory (API AD)

Llaverito valida a las personas contra AD usando la **API AD v1** (`POST /login`, `POST /gruposUser`) y usa la **API AD v2**
solo para saber si la cuenta sigue activa. Las cuentas de AD se crean solas en el primer ingreso (rol `viewer` y sin acceso
a ninguna carpeta hasta que un administrador lo conceda, o hasta que su grupo de AD lo defina).

Variables (`LLAVERITO_*`):

| Variable | Para qué |
|---|---|
| `AD_API_URL` | Base de la API AD v1, **https** obligatorio (ej. `https://api-ad.vicentelopez.gov.ar`). Vacío = login AD apagado |
| `AD_JWT_KEY` | Clave HS256 con la que la API AD firma sus respuestas (opcional, ver notas) |
| `AD_CA_FILE` | CA municipal, si el certificado de la API AD no es de una CA pública |
| `AD_ADMIN_GROUPS`, `AD_EDITOR_GROUPS` | Grupos de AD (separados por coma) que dan rol admin/editor. Con esto el rol **lo manda AD** y se actualiza en cada ingreso |
| `AD_ALLOWED_GROUPS` | Si se define, solo entran miembros de estos grupos (o de los de admin/editor). **Recomendado**: sin esto entra cualquier empleado como lector |
| `AD_V2_URL`, `AD_V2_API_KEY` | API AD v2 y una API key propia de Llaverito (`npm run claves -- agregar llaverito` en la VM de la v2) |
| `AD_V2_CACHE_SECONDS`, `AD_V2_STALE_SECONDS` | Caché (300 s) y ventana de gracia si la v2 no responde (24 h; pasada la ventana se corta el acceso) |

Qué hace con la v2: cada sesión web y cada token de agente de una cuenta de AD se revalida contra `GET /empleados/{usuario}`.
Si RRHH da de baja a la persona, **pierde la sesión y todos sus agentes MCP** en minutos, sin que nadie tenga que revocar nada.

Reglas de seguridad del login AD:

- Solo se acepta `usuario@vicentelopez.gov.ar` con caracteres seguros. **Un número (legajo) nunca se reenvía a la API AD**: la v1
  lo manda a otra base con una ruta distinta (ver hallazgos más abajo).
- Contraseña vacía o de más de 256 caracteres: se rechaza sin consultar a AD.
- La identidad que devuelve la API AD debe coincidir con la pedida; si no, se rechaza.
- Respuestas con `alg=none`, firma inválida (si hay `AD_JWT_KEY`), estado distinto de 200 o ilegibles: **se falla cerrado** (503).
- Con grupos configurados, si no se pueden leer los grupos, no se entra.
- Las cuentas de AD no tienen contraseña local (hash inutilizable). Una cuenta local con el mismo email **no** se pisa ni se fusiona.
- Revelar un secreto reconfirma la contraseña **contra AD** para esas cuentas. Las contraseñas no se guardan ni se auditan.
- Si cambian los grupos de una persona, el rol se actualiza en su próximo ingreso y las sesiones anteriores dejan de valer.
- Se mantiene una cuenta local de administrador como acceso de emergencia (`llaverito create-admin`).

### Hallazgos sobre la API AD v1 (para el equipo que la mantiene)

Detectados al leer el repositorio para integrarla; no afectan a Llaverito por las reglas de arriba, pero conviene corregirlos:

1. `index.js` tiene **credenciales de bases de datos escritas en el código**, versionadas en el repositorio. Rotarlas y pasarlas a variables de entorno.
2. La **clave de firma de los JWT es una sola, compartida, y figura en el README y en el código**. Cualquiera con acceso al repo puede fabricar
   una respuesta válida: la firma sirve como control de integridad, no de autenticidad. Mover la clave a configuración y, idealmente, una por consumidor.
3. La ruta de **legajo** arma la consulta SQL concatenando `usuario` y `clave` (inyección SQL) y compara la contraseña de la Web del Empleado en el propio SQL.
4. Se conecta a AD por **`ldap://` sin TLS**: las contraseñas viajan en claro entre la API y el controlador de dominio. Usar `ldaps://`.
5. Los JWT no llevan `exp` ni `iat` (se pueden reutilizar) y la ruta interna de `/login` es HTTP.
6. `POST /gruposUser` devuelve 500 para usuarios sin grupos (paréntesis mal ubicado en `jwt.sign`). Llaverito lo trata como falla cerrada.

## Compartir credenciales (por poco tiempo o permanente)

Además del acceso por carpeta, quien tiene **escritura** sobre una credencial puede compartirla con una persona concreta
(botón **Compartir…** en el detalle). La persona la ve en **Compartidas conmigo**, sin ver el resto de la carpeta.

| | |
|---|---|
| **Duración** | 15 min, 1 h, 8 h, 24 h, 7 d, 30 d o **permanente** (por API: `expires_in_minutes`, de 5 min a 1 año, o `null`) |
| **Nivel `reveal`** | Puede usarla con sus agentes **y ver el valor** (reconfirmando su contraseña, como siempre) |
| **Nivel `use`** | Puede usarla con sus agentes pero **no ver el valor**. No se puede dar a un lector (los lectores no crean agentes) |
| **Vencimiento** | Se evalúa en cada consulta: al pasar la hora, la persona deja de ver la credencial y **sus agentes también dejan de poder usarla**, sin tareas programadas. Compartir de nuevo renueva el plazo (o la vuelve permanente) |
| **Límites** | Lo compartido no permite editar, borrar ni volver a compartir. Si la credencial tiene "no revelar", ni siquiera `reveal` la muestra. Si la persona ya tiene la carpeta, no hace falta (409) |
| **Auditoría** | `credential_share`, `credential_share_update`, `credential_unshare`; los *reveal* indican `via: share`. Las compartidas vencidas quedan en el historial |

API: `GET/POST /api/credentials/{id}/shares`, `DELETE /api/credentials/{id}/shares/{share_id}`, `GET /api/credentials?shared=true`,
`GET /api/users/directory` (personas activas con las que se puede compartir; no disponible para lectores).
Las aprobaciones de un agente las ve y decide su dueño mientras siga teniendo acceso, también por compartido.

Para compartir **carpetas** completas sigue valiendo el acceso por carpeta (`Usuarios → Acceso`), que hoy es permanente.
Un agente tiene su propio vencimiento (`expires_in_days` al crearlo).

## Conectar un agente

1. En la UI: **Agentes → Nuevo agente**, elegir carpetas. Se muestra el token **una sola vez**.
2. Claude Code:

```bash
claude mcp add --transport http llaverito https://llaverito.vicentelopez.gov.ar/mcp \
  --header "Authorization: Bearer llv_..."
```

Tools: `list_credentials`, `http_request`, `ssh_exec`, `get_approval_status`. Ninguna devuelve secretos.

## Cómo protege los secretos

| Riesgo | Control |
|---|---|
| El agente lee el secreto | Ninguna tool lo devuelve; la salida pasa por un redactor (valor crudo, base64, URL-encoding, hex, líneas de claves PEM) |
| Inyección de prompt manda la clave a un host atacante | Allowlist de hosts **obligatoria** por credencial; sin redirecciones; sin `user:pass@` ni placeholders en el host |
| SSRF / DNS rebinding | Se resuelve el nombre y se valida **cada IP** antes de conectar; loopback y link-local siempre bloqueados; redes privadas solo si la credencial lo permite |
| Comando SSH malicioso | Lista de comandos sin aprobación; los comodines no cubren `; \| & $ \` ( )`; el resto exige aprobación humana |
| MITM en SSH | Clave del host **fijada por un humano** (huella SHA256) y verificada antes de enviar credenciales |
| Aprobación reutilizada | Un solo uso, atada a los parámetros exactos, con vencimiento |
| Robo de la base | Cifrado por sobre AES-256-GCM (DEK por secreto, AAD = id de credencial); la KEK no está en la base |
| Manipulación del log | Auditoría append-only con cadena de hashes (`GET /api/audit/verify`); nunca registra valores secretos |
| Agente con permisos de más | Un agente actúa con el acceso **vigente** de su dueño: si el dueño pierde la carpeta, se desactiva o pasa a lector, el agente deja de funcionar |
| Sesión robada | JWT firmado con clave derivada de la KEK; `logout` invalida el token en el servidor; bloqueo por IP+email y por email (ataques distribuidos); revelar exige reconfirmar contraseña con límite de intentos |
| Blob de cifrado alterado o movido | El AAD liga el cifrado al id de la credencial; ante fallo de integridad se cierra sin filtrar datos y se audita |
| CSRF / XSS | Cookie `HttpOnly` + `SameSite=Strict`, cabecera anti-CSRF, CSP estricta, UI sin `innerHTML` |

## Modelo de amenazas (qué se confía)

- **Administradores**: confiables; controlan usuarios, carpetas y ven la auditoría.
- **Editores**: confiables dentro de sus carpetas. Pueden revelar sus secretos y definir hosts permitidos/destino SSH de
  esas credenciales (por eso también pueden usar "escanear host" contra el destino que ellos mismos configuren).
- **Agentes**: no confiables (pueden ser manipulados por inyección de prompt). Solo reciben el resultado de acciones permitidas.
- **El servidor**: puede descifrar en memoria (necesario para el broker). Protegerlo es protegerlo todo: red interna, hardening,
  backups cifrados, acceso mínimo a la base y a la KEK. Los secretos en memoria de Python no se pueden borrar de forma garantizada.

## Límites conocidos (pendientes)

- **Autenticación de personas**: login por AD vía API AD (arriba) y cuentas locales (Argon2). Falta MFA y SSO por redirección (OIDC/SAML): hoy Llaverito sí recibe la contraseña de AD, aunque no la guarda.
- Cambiar el esquema (por ejemplo las columnas nuevas de usuarios de AD) requiere recrear la base de desarrollo: todavía no hay migraciones.
- **Clave maestra** en archivo/variable de entorno: falta unseal por Shamir o KMS/HSM, y rotación de la KEK.
- Los permisos de agentes (`AgentGrant.expires_at`) admiten vencimiento en el modelo pero la API/UI todavía no lo exponen.
- Los intentos de login fallidos se auditan: un atacante que varíe emails puede inflar la tabla (hay que rotar/archivar el log).
- Las contraseñas iniciales las define un admin y no se fuerza el cambio en el primer login.
- Sin migraciones (se usa `create_all`); agregar Alembic antes de cambiar el esquema en producción.
- Límite de intentos de login y rate limit de agentes **en memoria por proceso**: con varios workers, mover a Redis/DB.
- La IP del cliente es la del socket; detrás de un proxy hay que configurar cabeceras `X-Forwarded-For` de confianza.
- La salida SSH se acota al terminar el comando (no se corta en streaming).
- El redactor es una mitigación: un servidor remoto puede devolver el secreto transformado. La allowlist de destino es la defensa principal.
- Docker y PostgreSQL no se probaron todavía en este entorno (los tests corren sobre SQLite).
- Fases 3–4 del diseño (terminal SSH web, rotación automática, login por navegador, importadores) no están implementadas.
