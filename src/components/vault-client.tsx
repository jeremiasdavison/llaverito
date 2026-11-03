"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/client-api";
import { useVault } from "@/components/vault-gate";
import { apiKeyHint, sshFingerprint, type Envelope, type SealedPayload } from "@/lib/vault-crypto";

type Access = "owner" | "admin" | "use";
type Folder = {
  id: string;
  name: string;
  kind: "personal" | "project";
  githubRepo: string | null;
  access: Access;
};
type VaultItem = {
  id: string;
  folderId: string;
  name: string;
  kind: "api_key" | "ssh_key";
  fingerprint: string | null;
  revokedAt: string | null;
  access: Access;
  sharedDirectly: boolean;
};
type ShareRow = { id: string; granteeEmail: string; permission: "use" | "admin"; status?: string };
type Manifest = {
  githubRepo: string | null;
  entries: { bindingId: string; envKey: string; itemName: string; revoked: boolean; value: null }[];
};

export function VaultClient() {
  const vault = useVault();
  const [folders, setFolders] = useState<Folder[]>([]);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [shares, setShares] = useState<ShareRow[]>([]);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [panel, setPanel] = useState<"save" | "show" | "share" | "env" | null>("save");

  async function load() {
    const data = await api<{ folders: Folder[]; items: VaultItem[] }>("/api/vault");
    setFolders(data.folders);
    setItems(data.items);
    setSelected((current) => current ?? data.folders[0]?.id ?? null);
  }

  useEffect(() => {
    void load().catch((cause: Error) => setError(cause.message));
  }, []);

  const folder = folders.find((entry) => entry.id === selected) ?? null;
  const visible = useMemo(
    () => items.filter((entry) => (folder ? entry.folderId === folder.id : entry.sharedDirectly)),
    [items, folder],
  );
  const canAdmin = folder?.access === "owner" || folder?.access === "admin";

  useEffect(() => {
    if (!folder || !canAdmin) {
      setShares([]);
      setManifest(null);
      return;
    }
    void api<ShareRow[]>(`/api/shares?resourceType=folder&resourceId=${folder.id}`)
      .then(setShares)
      .catch((cause: Error) => setError(cause.message));
    if (folder.kind === "project") {
      void api<Manifest>(`/api/folders/${folder.id}/env`)
        .then(setManifest)
        .catch((cause: Error) => setError(cause.message));
    } else setManifest(null);
  }, [folder, canAdmin]);

  async function onCreateFolder(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await api("/api/folders", {
      method: "POST",
      body: JSON.stringify({
        name: String(form.get("name") ?? ""),
        kind: "project",
        githubRepo: String(form.get("githubRepo") ?? ""),
      }),
    });
    event.currentTarget.reset();
    await load();
  }

  async function onCreateItem(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!folder) return;
    const form = new FormData(event.currentTarget);
    const secret = String(form.get("secret") ?? "");
    const kind = String(form.get("kind") ?? "api_key");
    const publicKey = String(form.get("publicKey") ?? "");
    const envelope = await vault.encrypt(secret);
    const fingerprint = kind === "ssh_key" ? await sshFingerprint(publicKey) : apiKeyHint(secret);
    await api("/api/items", {
      method: "POST",
      body: JSON.stringify({
        folderId: folder.id,
        name: String(form.get("name") ?? ""),
        kind,
        fingerprint,
        envelope,
      }),
    });
    event.currentTarget.reset();
    await load();
  }

  async function revoke(id: string) {
    if (!window.confirm("¿Revocar este secreto? No se puede volver a abrir.")) return;
    await api(`/api/items/${id}`, { method: "DELETE" });
    setSecret(null);
    await load();
  }

  async function unlock(event: React.FormEvent<HTMLFormElement>, id: string) {
    event.preventDefault();
    const material = await api<Envelope & { mode: "owner" | "shared"; seal?: SealedPayload }>(`/api/items/${id}/envelope`);
    const opened = material.mode === "shared" && material.seal
      ? await vault.openShared(material, material.seal)
      : await vault.decryptOwned(material);
    setSecret(opened);
    await api(`/api/items/${id}/unlock`, { method: "POST", body: JSON.stringify({ confirm: true }) });
  }

  async function wrapShare(share: ShareRow) {
    const key = await api<{ publicKey: string }>(`/api/vault/public-key?email=${encodeURIComponent(share.granteeEmail)}`);
    const targets = visible.filter((entry) => !entry.revokedAt);
    const wraps = [];
    for (const entry of targets) {
      const material = await api<Envelope>(`/api/items/${entry.id}/envelope`);
      wraps.push({ itemId: entry.id, seal: await vault.wrapItemFor(material, key.publicKey) });
    }
    if (!wraps.length) throw new Error("No hay secretos activos para envolver");
    await api(`/api/shares/${share.id}/keys`, { method: "POST", body: JSON.stringify({ wraps }) });
    if (folder) setShares(await api(`/api/shares?resourceType=folder&resourceId=${folder.id}`));
  }

  async function onShare(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!folder) return;
    const form = new FormData(event.currentTarget);
    await api("/api/shares", {
      method: "POST",
      body: JSON.stringify({
        resourceType: "folder",
        resourceId: folder.id,
        grantee: String(form.get("grantee") ?? ""),
        permission: String(form.get("permission") ?? "use"),
      }),
    });
    event.currentTarget.reset();
    setShares(await api(`/api/shares?resourceType=folder&resourceId=${folder.id}`));
  }

  async function onBind(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!folder) return;
    const form = new FormData(event.currentTarget);
    await api(`/api/folders/${folder.id}/env`, {
      method: "POST",
      body: JSON.stringify({
        itemId: String(form.get("itemId") ?? ""),
        envKey: String(form.get("envKey") ?? ""),
      }),
    });
    event.currentTarget.reset();
    setManifest(await api(`/api/folders/${folder.id}/env`));
  }

  return (
    <section>
      <div className="vault-head">
        <h1>{folder ? folder.name : "Bóveda"}</h1>
        <p className="note">{visible.length === 1 ? "1 llave" : `${visible.length} llaves`}</p>
      </div>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      <div className="layout">
        <div className="ring">
          {folders.map((entry) => (
            <button
              key={entry.id}
              className="bow"
              type="button"
              aria-pressed={entry.id === selected}
              onClick={() => {
                setSelected(entry.id);
                setSecret(null);
                setError(null);
              }}
            >
              <span aria-hidden="true" />
              <div>
                {entry.name}
                <small>{entry.kind === "project" ? "Proyecto" : "Personal"}</small>
              </div>
            </button>
          ))}
          <form className="ticket" onSubmit={(event) => void onCreateFolder(event).catch((cause: Error) => setError(cause.message))}>
            <h2>Nueva carpeta</h2>
            <label>
              Nombre
              <input name="name" required maxLength={80} />
            </label>
            <label>
              Repo, si corresponde
              <input name="githubRepo" placeholder="owner/repo" />
            </label>
            <button className="btn" type="submit">Crear carpeta</button>
          </form>
        </div>
        <div>
          {folder ? (
            <>
              {folder.githubRepo ? <p className="note">Vinculada a {folder.githubRepo}</p> : null}
              <div>
                {visible.length === 0 ? <p>Esta carpeta no tiene llaves. Guardá la primera abajo.</p> : null}
                {visible.map((entry) => (
                  <article key={entry.id} className={`key-row ${entry.revokedAt ? "revoked" : ""}`}>
                    <div>
                      <strong>{entry.name}</strong>
                      <div className="note">{entry.fingerprint ?? "Sin huella"}</div>
                    </div>
                    <div>{entry.kind === "api_key" ? "API" : "SSH"}</div>
                    <div>{entry.revokedAt ? "Revocada" : entry.access === "owner" ? "Dueño" : entry.access === "admin" ? "Admin" : "Uso"}</div>
                    {canAdmin && !entry.revokedAt ? (
                      <button className="btn-danger" type="button" onClick={() => void revoke(entry.id).catch((cause: Error) => setError(cause.message))}>
                        Revocar
                      </button>
                    ) : <span />}
                  </article>
                ))}
              </div>
              {canAdmin ? (
                <div className="ticket-actions">
                  {(["save", "show", "share", "env"] as const)
                    .filter((name) => name !== "env" || folder.kind === "project")
                    .map((name) => (
                      <button
                        key={name}
                        className={panel === name ? "btn" : "btn-ghost"}
                        type="button"
                        aria-pressed={panel === name}
                        onClick={() => setPanel(name)}
                      >
                        {name === "save" ? "Guardar" : name === "show" ? "Mostrar" : name === "share" ? "Compartir" : "Variables"}
                      </button>
                    ))}
                </div>
              ) : null}
              {canAdmin && panel === "save" ? (
                <form className="sheet" onSubmit={(event) => void onCreateItem(event).catch((cause: Error) => setError(cause.message))}>
                  <h2>Guardar una llave</h2>
                  <label>
                    Nombre
                    <input name="name" required maxLength={120} />
                  </label>
                  <label>
                    Tipo
                    <select name="kind" defaultValue="api_key">
                      <option value="api_key">API key</option>
                      <option value="ssh_key">Clave SSH privada</option>
                    </select>
                  </label>
                  <label>
                    Secreto
                    <textarea name="secret" required minLength={8} autoComplete="off" spellCheck={false} />
                  </label>
                  <label>
                    Clave pública SSH, si la tenés
                    <textarea name="publicKey" spellCheck={false} placeholder="ssh-ed25519 AAAA..." />
                  </label>
                  <button className="btn" type="submit">Guardar cifrada</button>
                </form>
              ) : null}
              {canAdmin && panel === "show" && visible.some((entry) => !entry.revokedAt) ? (
                <form className="sheet" onSubmit={(event) => {
                  const id = String(new FormData(event.currentTarget).get("itemId") ?? "");
                  void unlock(event, id).catch((cause: Error) => setError(cause.message));
                }}>
                  <h2>Mostrar una vez</h2>
                  <p className="note">Se descifra en este navegador. Queda anotado en la auditoría.</p>
                  <label>
                    Llave
                    <select name="itemId">
                      {visible.filter((entry) => !entry.revokedAt).map((entry) => (
                        <option key={entry.id} value={entry.id}>{entry.name}</option>
                      ))}
                    </select>
                  </label>
                  <label className="check">
                    <input name="confirm" type="checkbox" required />
                    Mostrala en esta pantalla.
                  </label>
                  <button className="btn" type="submit">Mostrar</button>
                  {secret ? (
                    <label>
                      Secreto
                      <textarea className="secret-box" readOnly value={secret} />
                    </label>
                  ) : null}
                  {secret ? (
                    <button className="btn-ghost" type="button" onClick={() => setSecret(null)}>Ocultar</button>
                  ) : null}
                </form>
              ) : null}
              {canAdmin && panel === "share" ? (
                <form className="sheet" onSubmit={(event) => void onShare(event).catch((cause: Error) => setError(cause.message))}>
                  <h2>Compartir esta carpeta</h2>
                  <p className="note">La invitación queda pendiente hasta que envuelvas las llaves. El texto plano no sale.</p>
                  <label>
                    Email o id
                    <input name="grantee" required />
                  </label>
                  <label>
                    Permiso
                    <select name="permission" defaultValue="use">
                      <option value="use">Uso</option>
                      <option value="admin">Admin</option>
                    </select>
                  </label>
                  <button className="btn" type="submit">Invitar</button>
                  <div>
                    {shares.map((share) => (
                      <div className="share-line" key={share.id}>
                        <span>{share.granteeEmail}</span>
                        <span>{share.permission === "admin" ? "Admin" : "Uso"}</span>
                        <span>{share.status === "approved" ? "Envuelto" : "Pendiente"}</span>
                        {share.status !== "approved" ? (
                          <button
                            className="btn-ghost"
                            type="button"
                            onClick={() => void wrapShare(share).catch((cause: Error) => setError(cause.message))}
                          >
                            Aprobar y envolver
                          </button>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </form>
              ) : null}
              {canAdmin && panel === "env" && folder.kind === "project" ? (
                <form className="sheet" onSubmit={(event) => void onBind(event).catch((cause: Error) => setError(cause.message))}>
                  <h2>Variables del proyecto</h2>
                  <p className="note">El manifiesto no incluye valores.</p>
                  <label>
                    Llave
                    <select name="itemId">
                      {visible.filter((entry) => !entry.revokedAt).map((entry) => (
                        <option key={entry.id} value={entry.id}>{entry.name}</option>
                      ))}
                    </select>
                  </label>
                  <label>
                    Variable
                    <input name="envKey" required placeholder="OPENAI_API_KEY" pattern="[A-Z][A-Z0-9_]{0,63}" />
                  </label>
                  <button className="btn" type="submit">Mapear</button>
                  <pre className="mono">{JSON.stringify(manifest ?? { entries: [] }, null, 2)}</pre>
                </form>
              ) : null}
            </>
          ) : (
            <p>Cargando la bóveda.</p>
          )}
        </div>
      </div>
    </section>
  );
}
