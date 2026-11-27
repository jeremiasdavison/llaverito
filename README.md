# Llaverito

Cofre para que un agente use API keys y claves SSH sin ver el secreto. La persona guarda el material, el agente pide usarlo, y la aprobación devuelve un grant corto. El texto plano solo sale por un revelado explícito en la bóveda o por un sobre de un solo uso que abre el runner.

## Primer uso

1. Entrá a la URL del deploy y tocá **Crear cuenta**. No hay usuario de demostración.
2. La contraseña pide 12 caracteres o más, con letras y números, y rechaza contraseñas comunes o filtradas.
3. En **Bóveda** se crea sola la carpeta Personal.
4. En **Seguridad**, activá el autenticador (TOTP) y guardá los códigos de respaldo. Sin eso no se puede revelar, rotar un secreto, aprobar, compartir ni crear un token.
5. **Nuevo secreto**: nombre, tipo API key, y el valor. Guardar. La lista muestra una pista (`••••` y los últimos 4), no el secreto.
6. **Mostrar una vez** pide la contraseña y el código de 6 dígitos, revela el secreto en esa pantalla y lo anota en Auditoría.

## Variables

Copiá `.env.example` a `.env.local`. Generá cada secreto con `openssl rand -base64 32` y no lo subas. El detalle del deploy está en [docs/deploy.md](docs/deploy.md).

| Variable | Dónde | Notas |
| --- | --- | --- |
| `DATABASE_URL` | Vercel, tipo Secret, Production + Preview + Development | Postgres de Neon, string con pooler y `sslmode=require`. También se acepta `POSTGRES_URL`. La pone `vercel integration add neon`. |
| `BETTER_AUTH_SECRET` | Vercel, tipo Secret, los tres entornos | 32 caracteres o más. Distinto en Production y Preview si el equipo lo exige. |
| `BETTER_AUTH_URL` | Solo Production, tipo Config | `https://llaverito-six.vercel.app`. En Preview y en local, sin definir. |
| `ENCRYPTION_KEY` | Vercel, tipo Secret, los tres entornos | Base64 de 32 bytes. Cifra el material. Cambiarla deja los secretos viejos ilegibles. No la regeneres si ya está cargada. |
| `BETTER_AUTH_TRUSTED_ORIGINS` | Opcional | Orígenes exactos extra, separados por coma. Sin comodines. El deploy actual entra por `VERCEL_URL`. |
| `PWNED_PASSWORD_CHECK` | Opcional | `false` saltea la consulta a Have I Been Pwned en el alta. Si no está, la consulta está activa. |

En local: `npm install`, `npm run db:migrate`, `npm run dev`.

## Deploy en Vercel

Checklist para https://llaverito-six.vercel.app. Los valores salen de un archivo, no del argumento del comando.

```bash
npx vercel login
npx vercel link
npx vercel integration add neon --environment production --environment preview --environment development
```

Eso crea la base y carga `DATABASE_URL`. Si `BETTER_AUTH_SECRET` o `ENCRYPTION_KEY` todavía no existen:

```bash
openssl rand -base64 32 > /tmp/llaverito-encryption
openssl rand -base64 32 > /tmp/llaverito-auth
npx vercel env add ENCRYPTION_KEY production --type secret < /tmp/llaverito-encryption
npx vercel env add ENCRYPTION_KEY preview --type secret < /tmp/llaverito-encryption
npx vercel env add ENCRYPTION_KEY development --type secret < /tmp/llaverito-encryption
npx vercel env add BETTER_AUTH_SECRET production --type secret < /tmp/llaverito-auth
npx vercel env add BETTER_AUTH_SECRET preview --type secret < /tmp/llaverito-auth
npx vercel env add BETTER_AUTH_SECRET development --type secret < /tmp/llaverito-auth
rm /tmp/llaverito-encryption /tmp/llaverito-auth
printf 'https://llaverito-six.vercel.app' > /tmp/llaverito-url
npx vercel env add BETTER_AUTH_URL production --type config < /tmp/llaverito-url
rm /tmp/llaverito-url
npx vercel deploy --prod
```

`npm run build` aplica el esquema cuando la URL está en el entorno. Si no está, el build sigue y el primer request lo aplica. `npm run db:migrate` hace lo mismo a mano.

Verificación:

```bash
curl -sS https://llaverito-six.vercel.app/api/health
```

Tiene que dar 200 y `"ok": true`. Después creá la cuenta en `/sign-up`, entrá a `/app` y guardá un secreto. Si sigue en 503, el JSON dice qué variable falta (`missing`), cuál está mal (`invalid`) y si la base no está (`database: missing`) o no responde (`database: down`).

## Agente y entorno de proyecto

Una carpeta de proyecto puede mapear elementos a variables (`OPENAI_API_KEY`). **Solicitudes** arma el pedido. El manifiesto `GET /api/folders/:id/env` no trae valores. El canje, después de la aprobación, devuelve un sobre X25519 de un solo uso durante 2 minutos. El detalle del runner está en [docs/agente-ci.md](docs/agente-ci.md).

## Límites de este PoC

- No verifica el email. El alta sigue entrando sola (`autoSignIn`) para no cambiar ese flujo. Un alta repetida todavía se distingue de una contraseña débil en la API.
- El segundo factor es TOTP y hace falta para revelar, rotar un secreto, aprobar, compartir y emitir tokens. No es obligatorio para guardar un secreto ni para revocar.
- La confirmación reciente dura 5 minutos y no recuerda el dispositivo.
- No exporta un backup cifrado de la bóveda. Un dump de Neon sigue cifrado con `ENCRYPTION_KEY`.
- El límite de intentos vive en Postgres y, en el mismo proceso, en memoria. Si Postgres no responde, el intento se rechaza. No hay un WAF aparte.
- No hay rotación de `ENCRYPTION_KEY` ni borrado criptográfico más allá de pisar el sobre al revocar.
- El token de agente vence a los 90 días, se puede rotar y acepta los permisos `read`, `request` y `redeem`. La federación OIDC queda para después.
- Compartir con un email crea la invitación aunque esa persona todavía no tenga cuenta.
- No es un producto auditado. Sirve para guardar las primeras credenciales con cifrado, sesión y aprobación humana.
