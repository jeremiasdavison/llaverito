"use client";

import { useEffect, useMemo, useRef, useState } from "react";
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
type Tab = "items" | "env" | "access";

function message(cause: unknown) {
  return cause instanceof Error ? cause.message : "No se pudo completar";
}

function repoHref(slug: string | null) {
  if (!slug || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(slug)) return null;
  return `https://github.com/${slug}`;
}

export function VaultClient() {
  const [folders, setFolders] = useState<Folder[]>([]);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("items");
  const [error, setError] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [shares, setShares] = useState<ShareRow[]>([]);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [pending, setPending] = useState(false);
  const createRef = useRef<HTMLDialogElement>(null);
  const revealRef = useRef<HTMLDialogElement>(null);
  const folderRef = useRef<HTMLDialogElement>(null);

  async function load() {
    const data = await api<{ folders: Folder[]; items: VaultItem[] }>("/api/vault");
    setFolders(data.folders);
    setItems(data.items);
    setSelected((current) => current ?? data.folders[0]?.id ?? null);
  }

  useEffect(() => {
    void load().catch((cause: unknown) => setError(message(cause)));
  }, []);

  const folder = folders.find((entry) => entry.id === selected) ?? null;
  const visible = useMemo(
    () => items.filter((entry) => (folder ? entry.folderId === folder.id : entry.sharedDirectly)),
    [items, folder],
  );
  const canAdmin = folder?.access === "owner" || folder?.access === "admin";
  const activeItems = visible.filter((entry) => !entry.revokedAt);

  const folderId = folder?.id ?? null;
  const folderKind = folder?.kind ?? null;

  useEffect(() => {
    if (!folderId || !canAdmin) {
      setShares([]);
      setManifest(null);
      return;
    }
    void api<ShareRow[]>(`/api/shares?resourceType=folder&resourceId=${folderId}`)
      .then(setShares)
      .catch((cause: unknown) => setError(message(cause)));
    if (folderKind === "project") {
      void api<Manifest>(`/api/folders/${folderId}/env`)
        .then(setManifest)
        .catch((cause: unknown) => setError(message(cause)));
    } else setManifest(null);
  }, [folderId, folderKind, canAdmin]);

  function selectFolder(id: string) {
    setSelected(id);
    setTab("items");
    setSecret(null);
    setError(null);
    revealRef.current?.close();
  }

  async function onCreateFolder(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setPending(true);
    try {
      await api("/api/folders", {
        method: "POST",
        body: JSON.stringify({
          name: String(form.get("name") ?? ""),
          kind: "project",
          githubRepo: String(form.get("githubRepo") ?? ""),
        }),
      });
      event.currentTarget.reset();
      folderRef.current?.close();
      await load();
    } catch (cause) {
      setError(message(cause));
    } finally {
      setPending(false);
    }
  }

  async function onCreateItem(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!folder) return;
    const form = new FormData(event.currentTarget);
    setPending(true);
    try {
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
      createRef.current?.close();
      await load();
    } catch (cause) {
      setError(message(cause));
    } finally {
      setPending(false);
    }
  }

  async function revoke(id: string) {
    if (!window.confirm("¿Revocar este secreto? No se puede volver a abrir.")) return;
    await api(`/api/items/${id}`, { method: "DELETE" });
    setSecret(null);
    await load();
  }

  async function unlock(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const id = String(new FormData(event.currentTarget).get("itemId") ?? "");
    const data = await api<{ secret: string }>(`/api/items/${id}/unlock`, {
      method: "POST",
      body: JSON.stringify({ confirm: true }),
    });
    setCopied(false);
    setSecret(data.secret);
  }

  async function copySecret() {
    if (!secret) return;
    await navigator.clipboard.writeText(secret);
    setCopied(true);
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

  async function removeShare(id: string) {
    if (!folder) return;
    if (!window.confirm("¿Quitar este acceso?")) return;
    await api(`/api/shares/${id}`, { method: "DELETE" });
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

  async function unbind(bindingId: string) {
    if (!folder) return;
    await api(`/api/folders/${folder.id}/env/${bindingId}`, { method: "DELETE" });
    setManifest(await api(`/api/folders/${folder.id}/env`));
  }

  const href = repoHref(folder?.githubRepo ?? null);

  return (
    <section>
      <header className="page-head">
        <div>
          <p className="eyebrow">Bóveda</p>
          <h1>{folder?.name ?? "Carpetas"}</h1>
          <p className="note">La lista no trae secretos. Revelar es una acción aparte y queda en la auditoría.</p>
        </div>
        <div className="row-actions">
          <button className="btn-ghost" type="button" onClick={() => folderRef.current?.showModal()}>
            Nueva carpeta
          </button>
          {canAdmin ? (
            <button className="btn" type="button" onClick={() => createRef.current?.showModal()}>
              Nuevo secreto
            </button>
          ) : null}
        </div>
      </header>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      <div className="workspace">
        <div className="folder-list" aria-label="Carpetas">
          {folders.length === 0 ? <p className="empty">Todavía no hay carpetas.</p> : null}
          {folders.map((entry) => (
            <button
              key={entry.id}
              className="list-btn"
              type="button"
              aria-pressed={entry.id === selected}
              onClick={() => selectFolder(entry.id)}
            >
              <strong>{entry.name}</strong>
              <span className="tag">{entry.kind === "project" ? "proyecto" : "personal"}</span>
              <span className="faint">{entry.githubRepo ?? `${entry.access}`}</span>
            </button>
          ))}
        </div>
        <div className="stack">
          {folder ? (
            <>
              <div className="meta">
                <span className="pill">{folder.access}</span>
                {href ? (
                  <a href={href} rel="noreferrer">
                    {folder.githubRepo}
                  </a>
                ) : folder.githubRepo ? (
                  <span className="note">{folder.githubRepo}</span>
                ) : (
                  <span className="note">Sin repo asociado</span>
                )}
              </div>
              <div className="tabs" role="tablist" aria-label="Carpeta">
                <button className="tab" type="button" role="tab" aria-selected={tab === "items"} onClick={() => setTab("items")}>
                  Elementos
                </button>
                <button className="tab" type="button" role="tab" aria-selected={tab === "env"} onClick={() => setTab("env")} disabled={folder.kind !== "project"}>
                  Entorno
                </button>
                <button className="tab" type="button" role="tab" aria-selected={tab === "access"} onClick={() => setTab("access")}>
                  Acceso
                </button>
              </div>
              {tab === "items" ? (
                <div className="stack">
                  {visible.length === 0 ? (
                    <p className="empty">Esta carpeta no tiene elementos. Un secreto nuevo se cifra al guardarlo y no vuelve en la lista.</p>
                  ) : null}
                  {visible.map((entry) => (
                    <article key={entry.id} className={`panel item ${entry.revokedAt ? "revoked" : ""}`}>
                      <div>
                        <h3>{entry.name}</h3>
                        <div className="meta">
                          <span className="tag">{entry.kind === "api_key" ? "API" : "SSH"}</span>
                          <span className={entry.revokedAt ? "pill bad" : "pill ok"}>{entry.revokedAt ? "revocado" : "activo"}</span>
                          <span className="mono faint">{entry.fingerprint ?? "sin pista"}</span>
                        </div>
                      </div>
                      {canAdmin && !entry.revokedAt ? (
                        <div className="row-actions">
                          <button
                            className="btn-ghost"
                            type="button"
                            onClick={() => {
                              setSecret(null);
                              setCopied(false);
                              const select = revealRef.current?.querySelector("select");
                              if (select instanceof HTMLSelectElement) select.value = entry.id;
                              revealRef.current?.showModal();
                            }}
                          >
                            Revelar
                          </button>
                          <button className="btn-danger" type="button" onClick={() => void revoke(entry.id).catch((cause: unknown) => setError(message(cause)))}>
                            Revocar
                          </button>
                        </div>
                      ) : null}
                    </article>
                  ))}
                </div>
              ) : null}
              {tab === "env" ? (
                <div className="stack">
                  <div className="callout">
                    <strong>El manifiesto no trae valores.</strong>
                    <p>
                      Cada fila es un nombre de variable. Quien arma el proyecto no tiene que recibir un archivo por mail:
                      el runner pide este entorno y, después de la aprobación, abre un sobre. El acceso automático por
                      membresía del repo todavía no está en esta versión.
                    </p>
                  </div>
                  {canAdmin && activeItems.length > 0 ? (
                    <form className="panel inline-form" onSubmit={(event) => void onBind(event).catch((cause: unknown) => setError(message(cause)))}>
                      <h2>Mapear una variable</h2>
                      <label>
                        Elemento
                        <select name="itemId">
                          {activeItems.map((entry) => (
                            <option key={entry.id} value={entry.id}>{entry.name}</option>
                          ))}
                        </select>
                      </label>
                      <label>
                        Variable
                        <input name="envKey" required placeholder="OPENAI_API_KEY" pattern="[A-Z][A-Z0-9_]{0,63}" autoComplete="off" />
                      </label>
                      <button className="btn" type="submit">Mapear</button>
                    </form>
                  ) : null}
                  <div className="panel">
                    <table className="table">
                      <thead>
                        <tr>
                          <th>Variable</th>
                          <th>Secreto</th>
                          <th>Valor</th>
                          <th />
                        </tr>
                      </thead>
                      <tbody>
                        {(manifest?.entries ?? []).length === 0 ? (
                          <tr>
                            <td colSpan={4}>Todavía no hay variables.</td>
                          </tr>
                        ) : null}
                        {manifest?.entries.map((entry) => (
                          <tr key={entry.bindingId}>
                            <td className="mono">{entry.envKey}</td>
                            <td>{entry.itemName}</td>
                            <td>{entry.revoked ? "revocado" : "oculto en esta lista"}</td>
                            <td>
                              {canAdmin ? (
                                <button className="btn-ghost" type="button" onClick={() => void unbind(entry.bindingId).catch((cause: unknown) => setError(message(cause)))}>
                                  Quitar
                                </button>
                              ) : null}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : null}
              {tab === "access" ? (
                <div className="stack">
                  <div className="callout">
                    <strong>Compartir no manda el secreto.</strong>
                    <p>
                      Uso permite pedir una inyección. Admin administra la carpeta. Nadie recibe el texto plano en el
                      permiso. Cuando exista el chequeo contra GitHub o GitLab, perder el repo va a quitar el sobre.
                    </p>
                  </div>
                  {canAdmin ? (
                    <form className="panel inline-form" onSubmit={(event) => void onShare(event).catch((cause: unknown) => setError(message(cause)))}>
                      <h2>Invitar</h2>
                      <label>
                        Email o id de usuario
                        <input name="grantee" required autoComplete="off" />
                      </label>
                      <label>
                        Permiso
                        <select name="permission" defaultValue="use">
                          <option value="use">uso</option>
                          <option value="admin">admin</option>
                        </select>
                      </label>
                      <button className="btn" type="submit">Compartir</button>
                    </form>
                  ) : (
                    <p className="note">Tu acceso es de uso. No podés invitar ni revelar.</p>
                  )}
                  <div className="panel">
                    {shares.length === 0 ? <p className="empty">Nadie más tiene esta carpeta.</p> : null}
                    {shares.map((share) => (
                      <div className="person" key={share.id}>
                        <div>
                          <strong>{share.granteeEmail}</strong>
                          <div className="tag">{share.permission}</div>
                        </div>
                        {canAdmin ? (
                          <button className="btn-danger" type="button" onClick={() => void removeShare(share.id).catch((cause: unknown) => setError(message(cause)))}>
                            Quitar
                          </button>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </>
          ) : (
            <p className="empty">Cargando la bóveda…</p>
          )}
        </div>
      </div>

      <dialog ref={folderRef} aria-labelledby="folder-dialog-title" onClose={() => setPending(false)}>
        <form onSubmit={(event) => void onCreateFolder(event)}>
          <h2 id="folder-dialog-title">Carpeta de proyecto</h2>
          <p className="note">El repo es una etiqueta. Todavía no consulta la membresía en GitHub.</p>
          <label>
            Nombre
            <input name="name" required maxLength={80} />
          </label>
          <label>
            Repo de GitHub
            <input name="githubRepo" placeholder="owner/repo" autoComplete="off" />
          </label>
          <div className="row-actions">
            <button className="btn" type="submit" disabled={pending}>Crear carpeta</button>
            <button className="btn-ghost" type="button" onClick={() => folderRef.current?.close()}>Cancelar</button>
          </div>
        </form>
      </dialog>

      <dialog ref={createRef} aria-labelledby="item-dialog-title">
        <form onSubmit={(event) => void onCreateItem(event)}>
          <h2 id="item-dialog-title">Nuevo secreto</h2>
          <p className="note">Se envía una vez para cifrarlo. Después la lista solo guarda nombre y pista.</p>
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
          <div className="row-actions">
            <button className="btn" type="submit" disabled={pending}>Guardar cifrado</button>
            <button className="btn-ghost" type="button" onClick={() => createRef.current?.close()}>Cancelar</button>
          </div>
        </form>
      </dialog>

      <dialog
        ref={revealRef}
        aria-labelledby="reveal-dialog-title"
        onClose={() => {
          setSecret(null);
          setCopied(false);
        }}
      >
        <form onSubmit={(event) => void unlock(event).catch((cause: unknown) => setError(message(cause)))}>
          <h2 id="reveal-dialog-title">Revelar una vez</h2>
          <p className="note">El valor queda en esta ventana hasta que la cierres. No está en la lista ni en el registro.</p>
          <label>
            Elemento
            <select name="itemId">
              {activeItems.map((entry) => (
                <option key={entry.id} value={entry.id}>{entry.name}</option>
              ))}
            </select>
          </label>
          <label className="check">
            <input name="confirm" type="checkbox" required />
            Entiendo que el secreto se va a mostrar en esta pantalla.
          </label>
          <div className="row-actions">
            <button className="btn-ghost" type="submit">Mostrar</button>
            <button
              className="btn"
              type="button"
              onClick={() => {
                revealRef.current?.close();
              }}
            >
              Cerrar y ocultar
            </button>
          </div>
          {secret ? (
            <label>
              Secreto
              <textarea className="secret-box" readOnly value={secret} spellCheck={false} />
            </label>
          ) : null}
          {secret ? (
            <button className="btn-ghost" type="button" onClick={() => void copySecret().catch(() => setCopied(false))}>
              {copied ? "Copiado en el portapapeles" : "Copiar"}
            </button>
          ) : null}
        </form>
      </dialog>
    </section>
  );
}
