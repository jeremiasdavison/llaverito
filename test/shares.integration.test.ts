import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { eq } from "drizzle-orm";

process.env.BETTER_AUTH_SECRET = crypto.randomBytes(32).toString("base64");
process.env.ENCRYPTION_KEY = Buffer.alloc(32, 9).toString("base64");
process.env.PWNED_PASSWORD_CHECK = "false";
delete process.env.BETTER_AUTH_URL;
delete process.env.DATABASE_URL;
delete process.env.POSTGRES_URL;

const { PGlite } = await import("@electric-sql/pglite");
const { drizzle } = await import("drizzle-orm/pglite");
const { applySchemaStatements } = await import("../src/lib/migrate-sql.ts");
const { useTestDatabase } = await import("../src/lib/db.ts");
const { schema, accessRequest, share, user } = await import("../src/lib/schema.ts");
const { HttpError } = await import("../src/lib/errors.ts");

const client = await PGlite.create();
const migrate = () =>
  applySchemaStatements(async (statement, params) => {
    if (params && params.length > 0) await client.query(statement, params);
    else await client.exec(statement);
  });
await migrate();
const db = drizzle(client, { schema });
useTestDatabase(db);

const { getAuth } = await import("../src/lib/auth.ts");
const { folderAccess, itemAccess } = await import("../src/lib/access.ts");
const vault = await import("../src/lib/vault.ts");
const requests = await import("../src/lib/requests.ts");

type Actor = { id: string; email: string; name: string };

const origin = "https://llaverito-six.vercel.app";
const password = "correct-horse-1";
const secretValue = "sk-test-share-value-not-real";

async function signUp(email: string, name: string): Promise<Actor> {
  const auth = await getAuth();
  const response = await auth.handler(
    new Request(`${origin}/api/auth/sign-up/email`, {
      method: "POST",
      headers: { "content-type": "application/json", origin },
      body: JSON.stringify({ email, password, name }),
    }),
  );
  const text = await response.text();
  assert.equal(response.status, 200, text);
  const body = JSON.parse(text) as { user: { id: string; email: string } };
  return { id: body.user.id, email: body.user.email, name };
}

async function projectWithItem(owner: Actor, name: string) {
  const created = await vault.createFolder(owner, { name, kind: "project" });
  const secret = await vault.createItem(owner, {
    folderId: created.id,
    name: `${name}-key`,
    kind: "api_key",
    secret: secretValue,
  });
  return { folderId: created.id, itemId: secret.id };
}

function wrapKey() {
  const { publicKey } = crypto.generateKeyPairSync("x25519");
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  return jwk.x;
}

async function statusOf(code: number, run: () => Promise<unknown>) {
  try {
    await run();
  } catch (error) {
    assert.ok(error instanceof HttpError, String(error));
    assert.equal(error.status, code, error.message);
    return error.message;
  }
  assert.fail(`se esperaba ${code}`);
}

async function lostAccess(actor: Actor, folderId: string, itemId: string) {
  await statusOf(404, () => folderAccess(actor, folderId));
  await statusOf(404, () => itemAccess(actor, itemId));
  const listed = await vault.listVault(actor);
  assert.equal(listed.folders.some((entry) => entry.id === folderId), false);
  assert.equal(listed.items.some((entry) => entry.id === itemId), false);
}

const owner = await signUp("owner@example.com", "Owner");
const friend = await signUp("friend@example.com", "Friend");

test("compartir con un email sin cuenta no crea fila y responde igual que un id inexistente", async () => {
  const { folderId, itemId } = await projectWithItem(owner, "pendiente");
  const ghost = "ghost@example.com";
  const byEmail = await statusOf(404, () =>
    vault.createShare(owner, { resourceType: "folder", resourceId: folderId, grantee: ghost, permission: "admin" }),
  );
  const byId = await statusOf(404, () =>
    vault.createShare(owner, {
      resourceType: "folder",
      resourceId: folderId,
      grantee: crypto.randomUUID(),
      permission: "admin",
    }),
  );
  assert.equal(byEmail, byId);
  assert.equal(byEmail, vault.GRANTEE_NOT_FOUND);
  assert.equal(byEmail.includes(ghost), false);
  const rows = await db.select().from(share).where(eq(share.resourceId, folderId));
  assert.equal(rows.length, 0);
  assert.deepEqual(await vault.listShares(owner, "folder", folderId), []);

  // Quien registra ese email después no hereda nada.
  const late = await signUp(ghost, "Late");
  await lostAccess(late, folderId, itemId);
});

test("compartir con una cuenta existente da acceso y lo ata al id, no al email", async () => {
  const { folderId, itemId } = await projectWithItem(owner, "compartida");
  const saved = await vault.createShare(owner, {
    resourceType: "folder",
    resourceId: folderId,
    grantee: "Friend@Example.com",
    permission: "use",
  });
  assert.ok(saved);
  const [row] = await db.select().from(share).where(eq(share.id, saved.id));
  assert.equal(row?.granteeUserId, friend.id);
  assert.equal((await folderAccess(friend, folderId)).access, "use");
  assert.equal((await itemAccess(friend, itemId)).access, "use");
  const listed = await vault.listShares(owner, "folder", folderId);
  assert.equal(listed[0]?.active, true);

  // El acceso sigue al userId: otra identidad con el mismo email en el actor no alcanza.
  const impostor = { id: crypto.randomUUID(), email: friend.email, name: "Impostor" };
  await statusOf(404, () => folderAccess(impostor, folderId));

  // Compartir por id también funciona.
  const other = await projectWithItem(owner, "por-id");
  await vault.createShare(owner, { resourceType: "item", resourceId: other.itemId, grantee: friend.id, permission: "use" });
  assert.equal((await itemAccess(friend, other.itemId)).access, "use");
});

test("la migración deja inactivas las filas legadas cuyo email se registró después", async () => {
  const { folderId, itemId } = await projectWithItem(owner, "legada");
  const old = new Date(Date.now() - 60_000);
  // Fila vieja hecha a un email sin cuenta (como en prod antes del arreglo).
  await db.insert(share).values({
    id: crypto.randomUUID(),
    resourceType: "folder",
    resourceId: folderId,
    granteeEmail: "squatter@example.com",
    granteeUserId: null,
    permission: "admin",
    createdBy: owner.id,
    createdAt: old,
  });
  // Fila vieja a una cuenta que ya existía al compartir.
  const keeper = await signUp("keeper@example.com", "Keeper");
  await db.update(user).set({ createdAt: new Date(old.getTime() - 60_000) }).where(eq(user.id, keeper.id));
  await db.insert(share).values({
    id: crypto.randomUUID(),
    resourceType: "folder",
    resourceId: folderId,
    granteeEmail: "keeper@example.com",
    granteeUserId: null,
    permission: "use",
    createdBy: owner.id,
    createdAt: old,
  });
  const squatter = await signUp("squatter@example.com", "Squatter");
  await migrate();
  const rows = await db.select().from(share).where(eq(share.resourceId, folderId));
  assert.equal(rows.find((entry) => entry.granteeEmail === "squatter@example.com")?.granteeUserId, null);
  assert.equal(rows.find((entry) => entry.granteeEmail === "keeper@example.com")?.granteeUserId, keeper.id);
  await lostAccess(squatter, folderId, itemId);
  assert.equal((await folderAccess(keeper, folderId)).access, "use");
  const listed = await vault.listShares(owner, "folder", folderId);
  assert.equal(listed.find((entry) => entry.granteeEmail === "squatter@example.com")?.active, false);
});

async function approvedGrant(requester: Actor, itemId: string) {
  const created = await requests.createItemRequest(
    requester,
    { itemIds: [itemId], purpose: "deploy", wrapPublicKey: wrapKey() },
    null,
  );
  await requests.decideRequest(owner, created.id, "approve");
  const status = await requests.agentRequestStatus(requester, created.id);
  assert.equal(status.status, "approved");
  assert.ok(status.grantId);
  return { requestId: created.id, grantId: status.grantId };
}

async function shareWithFriend(resourceType: "folder" | "item", resourceId: string) {
  const saved = await vault.createShare(owner, { resourceType, resourceId, grantee: friend.email, permission: "use" });
  assert.ok(saved);
  return saved.id;
}

async function requestStatus(id: string) {
  const [row] = await db.select({ status: accessRequest.status }).from(accessRequest).where(eq(accessRequest.id, id));
  return row?.status;
}

test("el canje funciona mientras el compartido existe", async () => {
  const { itemId } = await projectWithItem(owner, "canje-ok");
  await shareWithFriend("item", itemId);
  const { requestId, grantId } = await approvedGrant(friend, itemId);
  const redeemed = await requests.redeemGrant(friend, grantId);
  assert.equal(redeemed.sealed.alg, "X25519-HKDF-SHA256-AES-256-GCM");
  assert.equal(redeemed.entries[0]?.itemId, itemId);
  assert.equal(JSON.stringify(redeemed).includes(secretValue), false);
  assert.equal(await requestStatus(requestId), "consumed");
});

test("tras borrar el compartido el grant aprobado no entrega el sobre", async () => {
  const { itemId } = await projectWithItem(owner, "canje-revocado");
  const shareId = await shareWithFriend("item", itemId);
  const { requestId, grantId } = await approvedGrant(friend, itemId);
  await vault.deleteShare(owner, shareId);
  assert.equal(await requestStatus(requestId), "expired");
  const message = await statusOf(410, () => requests.redeemGrant(friend, grantId));
  assert.equal(message.includes(secretValue), false);
});

test("redeemGrant revalida el acceso aunque la solicitud siga aprobada", async () => {
  const { folderId, itemId } = await projectWithItem(owner, "canje-sin-limpieza");
  const shareId = await shareWithFriend("folder", folderId);
  const { requestId, grantId } = await approvedGrant(friend, itemId);
  // Se borra la fila sin pasar por deleteShare: el chequeo en el canje es el que corta.
  await db.delete(share).where(eq(share.id, shareId));
  assert.equal(await requestStatus(requestId), "approved");
  await statusOf(403, () => requests.redeemGrant(friend, grantId));
  assert.equal(await requestStatus(requestId), "expired");
  await statusOf(410, () => requests.redeemGrant(friend, grantId));
});

test("aprobar una solicitud cuyo solicitante perdió el acceso se rechaza", async () => {
  const { folderId, itemId } = await projectWithItem(owner, "aprobar-sin-acceso");
  const shareId = await shareWithFriend("folder", folderId);
  const created = await requests.createItemRequest(
    friend,
    { itemIds: [itemId], purpose: "deploy", wrapPublicKey: wrapKey() },
    null,
  );
  await db.delete(share).where(eq(share.id, shareId));
  await statusOf(409, () => requests.decideRequest(owner, created.id, "approve"));
  assert.equal(await requestStatus(created.id), "denied");
  const [row] = await db
    .select({ grantHash: accessRequest.grantHash })
    .from(accessRequest)
    .where(eq(accessRequest.id, created.id));
  assert.equal(row?.grantHash, null);
});

test("borrar el compartido rechaza las solicitudes pendientes de esa persona", async () => {
  const { folderId, itemId } = await projectWithItem(owner, "pendiente-revocada");
  const shareId = await shareWithFriend("folder", folderId);
  const created = await requests.createItemRequest(
    friend,
    { itemIds: [itemId], purpose: "deploy", wrapPublicKey: wrapKey() },
    null,
  );
  await vault.deleteShare(owner, shareId);
  assert.equal(await requestStatus(created.id), "denied");
});

test.after(async () => {
  await client.close();
});
