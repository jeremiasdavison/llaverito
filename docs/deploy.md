# Deploy

Producción: https://llaverito-six.vercel.app

Conectar Neon y cargar las variables alcanza para crear una cuenta. El build aplica el esquema si ve `DATABASE_URL`. Si la variable solo existe en runtime, el mismo SQL corre en el primer request (`/api/health` incluido). Las sentencias son `IF NOT EXISTS` y quedan anotadas en `schema_migration` (hoy `0002_share_grantee_user`, que agrega `share.grantee_user_id` y deja inactivos los compartidos a emails que no tenían cuenta al compartir).

## Variables

Ningún valor real va en el repo. Generá secretos con `openssl rand -base64 32` y pasálos por un archivo, no por el historial del shell.

| Variable | Tipo en Vercel | Dónde | Qué va |
| --- | --- | --- | --- |
| `DATABASE_URL` | Secret | Production, Preview y Development | Connection string **pooled** de Neon, con `sslmode=require`. Si Neon inyecta `POSTGRES_URL` y no `DATABASE_URL`, también sirve. |
| `BETTER_AUTH_SECRET` | Secret | Production, Preview y Development | 32 caracteres o más. Si el equipo exige secretos distintos por entorno, no reutilices el de Production. |
| `ENCRYPTION_KEY` | Secret | Production, Preview y Development | Base64 de 32 bytes. Cifra el material. Cambiarla deja ilegibles los secretos ya guardados. |
| `BETTER_AUTH_URL` | Config | Solo Production | `https://llaverito-six.vercel.app`. En Preview y en local dejala sin definir. |

Hoy el health público dice `encryption: configured`. No vuelvas a escribir `ENCRYPTION_KEY` si ya hay un valor: pisarlo no se puede deshacer.

## Conectar Neon

En el directorio del repo, con la CLI logueada y el proyecto de https://llaverito-six.vercel.app linkeado:

```bash
npx vercel link
npx vercel integration add neon --environment production --environment preview --environment development
```

Eso instala la integración, crea la base y escribe `DATABASE_URL` (y en general `POSTGRES_URL`) en los tres entornos. No hace falta pegar el string a mano.

Si la integración no es una opción y ya tenés el string en un archivo fuera del repo:

```bash
npx vercel env add DATABASE_URL production --type secret < /ruta/fuera-del-repo/database-url
npx vercel env add DATABASE_URL preview --type secret < /ruta/fuera-del-repo/database-url
npx vercel env add DATABASE_URL development --type secret < /ruta/fuera-del-repo/database-url
```

Secretos de auth y cifrado, solo si todavía no existen. No los regeneres si ya están cargados.

```bash
openssl rand -base64 32 > /tmp/llaverito-auth
openssl rand -base64 32 > /tmp/llaverito-encryption
npx vercel env add BETTER_AUTH_SECRET production --type secret < /tmp/llaverito-auth
npx vercel env add BETTER_AUTH_SECRET preview --type secret < /tmp/llaverito-auth
npx vercel env add BETTER_AUTH_SECRET development --type secret < /tmp/llaverito-auth
npx vercel env add ENCRYPTION_KEY production --type secret < /tmp/llaverito-encryption
npx vercel env add ENCRYPTION_KEY preview --type secret < /tmp/llaverito-encryption
npx vercel env add ENCRYPTION_KEY development --type secret < /tmp/llaverito-encryption
rm /tmp/llaverito-auth /tmp/llaverito-encryption
printf 'https://llaverito-six.vercel.app' > /tmp/llaverito-url
npx vercel env add BETTER_AUTH_URL production --type config < /tmp/llaverito-url
rm /tmp/llaverito-url
```

Un cambio de variables no entra en el deploy que ya está publicado. Hace falta un deploy nuevo: push a `main`, o `npx vercel deploy --prod`.

## Migraciones

`npm run build` ejecuta `scripts/migrate.ts --if-configured` antes de `next build`.

- Con `DATABASE_URL` o `POSTGRES_URL` en el entorno del build, aplica el esquema y termina.
- Sin ninguna de las dos, avisa y el build sigue. El primer request aplica el mismo SQL.

A mano, contra la base que apunte la variable del entorno:

```bash
npm run db:migrate
```

En local: copiá `.env.example` a `.env.local`, completá los valores, y corré `npm run db:migrate` antes de `npm run dev`.

## Verificar

```bash
curl -sS https://llaverito-six.vercel.app/api/health
```

Tiene que responder 200 con `"ok": true`, `"database": "up"`, `"schema": "ready"`, `"encryption": "configured"` y `"authSecret": "configured"`. `missing` e `invalid` quedan vacíos. El campo `hint` dice que se puede crear una cuenta.

Después, en el navegador:

1. Abrí `/sign-up` y creá una cuenta (12 caracteres o más, con letras y números).
2. Tenés que quedar en `/app`, con la carpeta Personal.
3. Creá un secreto. La lista muestra una pista, no el valor.
4. Salí y volvé a entrar por `/sign-in` con el mismo email.

Si el health sigue en 503, leé `database`, `missing`, `invalid` y `hint`. No mires el log buscando el connection string: los errores de base se registran sin la URL.

| `database` | Qué pasa |
| --- | --- |
| `missing` | No está `DATABASE_URL` ni `POSTGRES_URL` en ese entorno. |
| `down` | La variable está, pero Neon no respondió. Revisá el string del pooler, `sslmode=require` y que el proyecto no esté suspendido. |
| `up` con `schema: failed` | La base responde y el DDL falló. Corré `npm run db:migrate` con esa URL y mirá el mensaje (la URL sale redactada). |
| `up` con `schema: ready` y `ok: false` | Falta o está mal `BETTER_AUTH_SECRET`, `ENCRYPTION_KEY` o `BETTER_AUTH_URL`. Los nombres están en `missing` o `invalid`. |

Crear cuenta contra una base caída responde 503 con un mensaje en español, no un 500 genérico.
