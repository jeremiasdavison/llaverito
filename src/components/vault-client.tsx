"use client";

import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/client-api";

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
type ShareRow = { id: string; granteeEmail: string; permission: "use" | "admin" };
type Manifest = {
  githubRepo: string | null;
  entries: { bindingId: string; envKey: string; itemName: string; revoked: boolean; value: null }[];
};

export function VaultClient() {
  const [folders, setFolders] = useState<Folder[]>([]);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [shares, setShares] = useState<ShareRow[]>([]);
  const [manifest, setManifest] = useState<Manifest | null>(null);

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
    await api("/api/items", {
      method: "POST",
      body: JSON.stringify({
        folderId: folder.id,
        name: String(form.get("name") ?? ""),
        kind: String(form.get("kind") ?? "api_key"),
        secret: String(form.get("secret") ?? ""),
        publicKey: String(form.get("publicKey") ?? ""),
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
    const data = await api<{ secret: string }>(`/api/items/${id}/unlock`, {
      method: "POST",
      body: JSON.stringify({ confirm: true }),
    });
    setSecret(data.secret);
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
      <h1>Bóveda</h1>
      <p className="note">La lista no trae secretos. Revelar uno es una acción aparte y queda en la auditoría.</p>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      <div className="layout">
        <div className="stack">
          {folders.map((entry) => (
            <button
              key={entry.id}
              className="list-btn"
              type="button"
              aria-pressed={entry.id === selected}
              onClick={() => {
                setSelected(entry.id);
                setSecret(null);
                setError(null);
              }}
            >
              <strong>{entry.name}</strong>
              <div className="tag">{entry.kind === "project" ? "proyecto" : "personal"}</div>
            </button>
          ))}
          <form className="stack" onSubmit={(event) => void onCreateFolder(event).catch((cause: Error) => setError(cause.message))}>
            <label>
              Nueva carpeta de proyecto
              <input name="name" required maxLength={80} placeholder="Nombre" />
            </label>
            <label>
              Repo de GitHub
              <input name="githubRepo" placeholder="owner/repo" />
            </label>
            <button className="btn" type="submit">Crear carpeta</button>
          </form>
        </div>
        <div className="stack">
          {folder ? (
            <>
              <h2>{folder.name}</h2>
              {folder.githubRepo ? <p className="note">Repo {folder.githubRepo}</p> : null}
              <div className="table">
                {visible.length === 0 ? <p className="note">Todavía no hay elementos.</p> : null}
                {visible.map((entry) => (
                  <article key={entry.id} className={`row ${entry.revokedAt ? "revoked" : ""}`}>
                    <div>
                      <strong>{entry.name}</strong>
                      <div className="note">{entry.fingerprint ?? "sin huella"}</div>
                    </div>
                    <div className="tag">{entry.kind === "api_key" ? "API" : "SSH"}</div>
                    <div>{entry.revokedAt ? "revocado" : entry.access}</div>
                    {canAdmin && !entry.revokedAt ? (
                      <button className="btn-danger" type="button" onClick={() => void revoke(entry.id).catch((cause: Error) => setError(cause.message))}>
                        Revocar
                      </button>
                    ) : <span />}
                  </article>
                ))}
              </div>
              {canAdmin ? (
                <form className="panel" onSubmit={(event) => void onCreateItem(event).catch((cause: Error) => setError(cause.message))} style={{ padding: 16 }}>
                  <h3>Nuevo secreto</h3>
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
                    Clave pública SSH, opcional
                    <textarea name="publicKey" spellCheck={false} placeholder="ssh-ed25519 AAAA... comentario" />
                  </label>
                  <button className="btn" type="submit">Guardar cifrado</button>
                </form>
              ) : null}
              {canAdmin && visible.some((entry) => !entry.revokedAt) ? (
                <form className="panel" style={{ padding: 16 }} onSubmit={(event) => {
                  const id = String(new FormData(event.currentTarget).get("itemId") ?? "");
                  void unlock(event, id).catch((cause: Error) => setError(cause.message));
                }}>
                  <h3>Revelar</h3>
                  <label>
                    Elemento
                    <select name="itemId">
                      {visible.filter((entry) => !entry.revokedAt).map((entry) => (
                        <option key={entry.id} value={entry.id}>{entry.name}</option>
                      ))}
                    </select>
                  </label>
                  <label className="check">
                    <input name="confirm" type="checkbox" required />
                    Entiendo que el secreto se va a mostrar en esta pantalla.
                  </label>
                  <button className="btn-ghost" type="submit">Mostrar una vez</button>
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
              {canAdmin ? (
                <form className="panel" style={{ padding: 16 }} onSubmit={(event) => void onShare(event).catch((cause: Error) => setError(cause.message))}>
                  <h3>Compartir carpeta</h3>
                  <p className="note">Uso permite pedir inyección. Admin administra. Nadie recibe el texto plano en el permiso.</p>
                  <label>
                    Email o id de usuario
                    <input name="grantee" required />
                  </label>
                  <label>
                    Permiso
                    <select name="permission" defaultValue="use">
                      <option value="use">uso</option>
                      <option value="admin">admin</option>
                    </select>
                  </label>
                  <button className="btn" type="submit">Compartir</button>
                  <ul>
                    {shares.map((share) => (
                      <li key={share.id}>{share.granteeEmail} · {share.permission}</li>
                    ))}
                  </ul>
                </form>
              ) : null}
              {canAdmin && folder.kind === "project" ? (
                <form className="panel" style={{ padding: 16 }} onSubmit={(event) => void onBind(event).catch((cause: Error) => setError(cause.message))}>
                  <h3>Entorno virtual</h3>
                  <p className="note">Mapeá nombres de secretos a variables. El manifiesto de abajo no tiene valores.</p>
                  <label>
                    Elemento
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
                  <pre className="mono">{JSON.stringify(manifest ?? { entries: [], value: null }, null, 2)}</pre>
                </form>
              ) : null}
            </>
          ) : (
            <p className="note">Cargando la bóveda…</p>
          )}
        </div>
      </div>
    </section>
  );
}
