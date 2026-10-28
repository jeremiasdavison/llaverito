# Cómo un agente o CI pide el entorno

Llaverito no entrega el secreto en la respuesta de aprobación. El runner, fuera del modelo, genera una clave X25519, pide el uso, espera la aprobación humana y abre un sobre de un solo uso.

## Identidad

El token de agente (`llv_…`) solo puede listar metadatos, crear solicitudes y canjear grants. No abre el texto plano. En producción conviene cambiarlo por OIDC de GitHub Actions para no guardar un token de larga vida. Este PoC todavía usa el token.

Crearlo en **Agentes**. Se muestra una sola vez. Guardarlo como secreto del CI con el nombre `LLAVERITO_TOKEN`.

## Manifiesto, sin valores

```bash
curl -sS "$LLAVERITO_URL/api/agent/folders/$FOLDER_ID/env" \
  -H "authorization: Bearer $LLAVERITO_TOKEN"
```

La respuesta trae `envKey`, nombre y si está revocado. `value` es siempre `null`.

## Pedido e inyección

En el runner, no en el prompt del modelo:

```bash
node --input-type=module -e '
import crypto from "node:crypto";
const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
const pub = Buffer.from(publicKey.export({ format: "der", type: "spki" })).subarray(-32).toString("base64url");
const priv = Buffer.from(privateKey.export({ format: "der", type: "pkcs8" })).subarray(-32).toString("base64url");
console.log(JSON.stringify({ pub, priv }));
' > /tmp/llaverito-wrap.json
```

`pub` va en el pedido. `priv` se queda en el runner.

```bash
curl -sS -X POST "$LLAVERITO_URL/api/agent/folders/$FOLDER_ID/env" \
  -H "authorization: Bearer $LLAVERITO_TOKEN" \
  -H "content-type: application/json" \
  -d "{\"purpose\":\"deploy\",\"wrapPublicKey\":\"$PUB\",\"repository\":\"owner/repo\"}"
```

Si la carpeta tiene `githubRepo`, `repository` tiene que coincidir.

Una persona aprueba en **Solicitudes**. La API de aprobación no devuelve el secreto ni el grant completo al navegador.

El agente consulta el estado y, recién aprobado, recibe `grantId`:

```bash
curl -sS "$LLAVERITO_URL/api/agent/requests/$REQUEST_ID" \
  -H "authorization: Bearer $LLAVERITO_TOKEN"
```

El canje es de un solo uso y dura 2 minutos:

```bash
curl -sS -X POST "$LLAVERITO_URL/api/agent/grants/redeem" \
  -H "authorization: Bearer $LLAVERITO_TOKEN" \
  -H "content-type: application/json" \
  -d "{\"grantId\":\"$GRANT_ID\"}" \
  -o /tmp/llaverito-sealed.json

LLAVERITO_WRAP_PRIVATE_KEY="$PRIV" node scripts/unseal.mjs /tmp/llaverito-sealed.json > "$RUNNER_TEMP/llaverito.env"
```

Cargar ese archivo en el entorno del job (`GITHUB_ENV` o equivalente) y borrarlo. No imprimir el archivo en los logs.

Para elementos sueltos, sin carpeta, el pedido es `POST /api/agent/requests` con `itemIds`. El mismo canje devuelve el sobre. Si no hay `envKey`, el script escribe `LLAVERITO_UNBOUND_N`.

## Qué no hace esta versión

No inyecta solo dentro de un sandbox de GitHub. No federa OIDC. No rota `ENCRYPTION_KEY`. El paso de aprobación sigue siendo una persona en la web de Llaverito.
