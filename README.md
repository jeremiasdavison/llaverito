# Llaverito

Cofre para que un agente use API keys y claves SSH sin ver el secreto. El cifrado es en el navegador, al estilo 1Password: cada secreto tiene una data key, y esa data key se envuelve con una clave derivada de la contraseña de la bóveda más una Secret Key que no se guarda en Supabase. Compartir vuelve a envolver la data key para la clave pública de la otra persona, después de una aprobación. El agente solo recibe un sobre.

## Primer uso

1. Entrá a la URL del deploy y tocá **Crear cuenta**. No hay usuario de demostración.
2. La contraseña pide 12 caracteres o más, con letras y números.
3. En **Bóveda** se crea sola la carpeta Personal.
4. **Nuevo secreto**: nombre, tipo API key, y el valor. Guardar. La lista muestra una pista (`••••` y los últimos 4), no el secreto.
5. **Mostrar una vez** lo revela en esa pantalla y lo anota en Auditoría.

## Variables

Copiá `.env.example` a `.env.local`. Generá cada secreto con `openssl rand -base64 32` y no lo subas.

| Variable | Dónde | Notas |
| --- | --- | --- |
| `DATABASE_URL` | Vercel, tipo Secret | Postgres de Supabase, string con pooler. También se acepta `POSTGRES_URL`. |
| `BETTER_AUTH_SECRET` | Vercel, tipo Secret | 32 caracteres o más. |
| `BETTER_AUTH_URL` | Solo Production | `https://llaverito-alpha.vercel.app`. En Preview dejala sin definir. |
| `GITHUB_CLIENT_ID` | Vercel, tipo Config | OAuth app de GitHub. |
| `GITHUB_CLIENT_SECRET` | Vercel, tipo Secret | Secreto de esa OAuth app. |

GitHub OAuth, lo crea Jeremías: Settings → Developer settings → OAuth Apps → New. Homepage `https://llaverito-alpha.vercel.app`. Callback `https://llaverito-alpha.vercel.app/api/auth/callback/github`.

Supabase, si no quedó provisionado: dashboard de Supabase → New project → Project Settings → Database → connection string (pooler, transaction) → `vercel env add DATABASE_URL`.

En local: `npm install`, `npm run db:migrate`, `npm run dev`.

## Deploy en Vercel

El CLI de este entorno no tiene sesión de Vercel. Falta este paso, a mano:

```bash
npx vercel login
npx vercel link
npx vercel integration add neon
openssl rand -base64 32 > /tmp/llaverito-encryption
openssl rand -base64 32 > /tmp/llaverito-auth
npx vercel env add ENCRYPTION_KEY production,preview --type secret < /tmp/llaverito-encryption
npx vercel env add ENCRYPTION_KEY development --type secret < /tmp/llaverito-encryption
npx vercel env add BETTER_AUTH_SECRET production,preview --type secret < /tmp/llaverito-auth
npx vercel env add BETTER_AUTH_SECRET development --type secret < /tmp/llaverito-auth
rm /tmp/llaverito-encryption /tmp/llaverito-auth
npx vercel deploy
```

Si la política del equipo pide un valor de Production distinto, generá otro archivo y no reutilices el de Preview. `BETTER_AUTH_URL` se agrega recién cuando exista el dominio de producción. Después de conectar Neon, un deploy nuevo toma `DATABASE_URL`. El esquema se crea solo en el primer request.

## Agente y entorno de proyecto

Una carpeta de proyecto puede mapear elementos a variables (`OPENAI_API_KEY`). **Solicitudes** arma el pedido. El manifiesto `GET /api/folders/:id/env` no trae valores. El canje, después de la aprobación, devuelve un sobre X25519 de un solo uso durante 2 minutos. El detalle del runner está en [docs/agente-ci.md](docs/agente-ci.md).

## Límites de este PoC

- No verifica el email ni pide un segundo factor para revelar.
- El límite de intentos de la app vive en Postgres; el de Better Auth también, pero no hay un WAF aparte.
- No hay rotación de `ENCRYPTION_KEY` ni borrado criptográfico más allá de pisar el sobre al revocar.
- El token de agente es un secreto de larga vida. La federación OIDC queda para después.
- Compartir con un email crea la invitación aunque esa persona todavía no tenga cuenta.
- No es un producto auditado. Sirve para guardar las primeras credenciales con cifrado, sesión y aprobación humana.
