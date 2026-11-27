"use client";

import { useEffect, useMemo, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { PageHeader } from "@/components/page-header";
import { useEphemeralSecret } from "@/components/use-ephemeral-secret";
import { api } from "@/lib/client-api";
import { errorMessage } from "@/lib/client-error";

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
type Phase = "loading" | "ready" | "error";

function repoHref(slug: string | null) {
  if (!slug || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(slug)) return null;
  return `https://github.com/${slug}`;
}

function wipeDialog(dialog: HTMLDialogElement) {
  const form = dialog.querySelector("form");
  form?.reset();
  form?.querySelectorAll("textarea, input").forEach((field) => {
    if (field instanceof HTMLTextAreaElement && !field.readOnly) field.value = "";
    if (field instanceof HTMLInputElement && field.type !== "checkbox" && field.type !== "radio") field.value = "";
    if (field instanceof HTMLInputElement && (field.type === "checkbox" || field.type === "radio")) field.checked = false;
  });
}

function openDialog(dialog: HTMLDialogElement | null) {
  if (!dialog || dialog.open) return;
  dialog.showModal();
}

export function VaultClient() {
  const [folders, setFolders] = useState<Folder[]>([]);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("items");
  const [phase, setPhase] = useState<Phase>("loading");
  const [error, setError] = useState<string | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  const [hiddenNote, setHiddenNote] = useState<string | null>(null);
  const [shares, setShares] = useState<ShareRow[]>([]);
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [revealId, setRevealId] = useState<string | null>(null);
  const [itemKind, setItemKind] = useState<"api_key" | "ssh_key">("api_key");
  const [maskSecret, setMaskSecret] = useState(true);
  const ephemeral = useEphemeralSecret();
  const revealed = useRef(false);
  const createRef = useRef<HTMLDialogElement>(null);
  const revealRef = useRef<HTMLDialogElement>(null);
  const folderRef = useRef<HTMLDialogElement>(null);

  async function load() {
    const data = await api<{ folders: Folder[]; items: VaultItem[] }>("/api/vault");
    setFolders(data.folders);
    setItems(data.items);
    setSelected((current) => current ?? data.folders[0]?.id ?? null);
    setPhase("ready");
    setError(null);
  }

  useEffect(() => {
    let cancelled = false;
    void load().catch((cause: unknown) => {
      if (cancelled) return;
      setError(errorMessage(cause));
      setPhase("error");
    });
    return () => {
      cancelled = true;
    };
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
    let cancelled = false;
    void api<ShareRow[]>(`/api/shares?resourceType=folder&resourceId=${folderId}`)
      .then((rows) => {
        if (!cancelled) setShares(rows);
      })
      .catch((cause: unknown) => {
        if (!cancelled) setError(errorMessage(cause));
      });
    if (folderKind === "project") {
      void api<Manifest>(`/api/folders/${folderId}/env`)
        .then((next) => {
          if (!cancelled) setManifest(next);
        })
        .catch((cause: unknown) => {
          if (!cancelled) setError(errorMessage(cause));
        });
    } else setManifest(null);
    return () => {
      cancelled = true;
    };
  }, [folderId, folderKind, canAdmin]);

  useEffect(() => {
    if (ephemeral.secret) {
      revealed.current = true;
      return;
    }
    if (revealed.current && revealRef.current?.open) {
      setHiddenNote("El secreto se ocultó de esta pantalla.");
    }
    revealed.current = false;
  }, [ephemeral.secret]);

  function selectFolder(id: string) {
    setSelected(id);
    setTab("items");
    setError(null);
    ephemeral.clear();
    setHiddenNote(null);
    revealRef.current?.close();
  }

  function closeAndWipe(dialog: HTMLDialogElement | null) {
    dialog?.close();
  }

  async function onCreateFolder(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy("folder");
    setDialogError(null);
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
      setDialogError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function onCreateItem(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!folder) return;
    const form = new FormData(event.currentTarget);
    setBusy("item");
    setDialogError(null);
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
      setDialogError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function revoke(id: string) {
    if (!window.confirm("¿Revocar este secreto? No se puede volver a abrir.")) return;
    setBusy(id);
    try {
      await api(`/api/items/${id}`, { method: "DELETE" });
      ephemeral.clear();
      await load();
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function unlock(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const id = String(new FormData(event.currentTarget).get("itemId") ?? "");
    setBusy("reveal");
    setDialogError(null);
    try {
      const data = await api<{ secret: string }>(`/api/items/${id}/unlock`, {
        method: "POST",
        body: JSON.stringify({ confirm: true }),
      });
      if (!revealRef.current?.open) return;
      setHiddenNote(null);
      ephemeral.reveal(data.secret);
    } catch (cause) {
      setDialogError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function copySecret() {
    try {
      await ephemeral.copy();
    } catch {
      setDialogError("No se pudo copiar. Seleccioná el texto y copialo a mano.");
    }
  }

  async function onShare(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!folder) return;
    const form = new FormData(event.currentTarget);
    setBusy("share");
    try {
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
      setError(null);
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function removeShare(id: string) {
    if (!folder) return;
    if (!window.confirm("¿Quitar este acceso?")) return;
    setBusy(id);
    try {
      await api(`/api/shares/${id}`, { method: "DELETE" });
      setShares(await api(`/api/shares?resourceType=folder&resourceId=${folder.id}`));
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function onBind(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!folder) return;
    const form = new FormData(event.currentTarget);
    setBusy("bind");
    try {
      await api(`/api/folders/${folder.id}/env`, {
        method: "POST",
        body: JSON.stringify({
          itemId: String(form.get("itemId") ?? ""),
          envKey: String(form.get("envKey") ?? ""),
        }),
      });
      event.currentTarget.reset();
      setManifest(await api(`/api/folders/${folder.id}/env`));
      setError(null);
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function unbind(bindingId: string) {
    if (!folder) return;
    if (!window.confirm("¿Quitar esta variable del entorno?")) return;
    setBusy(bindingId);
    try {
      await api(`/api/folders/${folder.id}/env/${bindingId}`, { method: "DELETE" });
      setManifest(await api(`/api/folders/${folder.id}/env`));
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  function openReveal(id: string) {
    ephemeral.clear();
    setRevealId(id);
    setDialogError(null);
    setHiddenNote(null);
    openDialog(revealRef.current);
  }

  const tabs: { id: Tab; label: string; disabled: boolean }[] = [
    { id: "items", label: "Elementos", disabled: false },
    { id: "env", label: "Entorno", disabled: folder?.kind !== "project" },
    { id: "access", label: "Acceso", disabled: false },
  ];

  function onTabsKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const enabled = tabs.filter((entry) => !entry.disabled);
    const index = enabled.findIndex((entry) => entry.id === tab);
    if (index < 0) return;
    let next = index;
    if (event.key === "ArrowRight") next = (index + 1) % enabled.length;
    else if (event.key === "ArrowLeft") next = (index - 1 + enabled.length) % enabled.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = enabled.length - 1;
    else return;
    event.preventDefault();
    const id = enabled[next]?.id;
    if (!id) return;
    setTab(id);
    document.getElementById(`tab-${id}`)?.focus();
  }

  const href = repoHref(folder?.githubRepo ?? null);

  return (
    <section aria-busy={phase === "loading"}>
      <PageHeader
        eyebrow="Bóveda"
        title={folder?.name ?? "Bóveda"}
        lede="La lista no trae secretos. Revelar es una acción aparte, queda en la auditoría y se oculta solo."
        actions={
          <>
            <button
              className="btn-ghost"
              type="button"
              onClick={() => {
                setDialogError(null);
                openDialog(folderRef.current);
              }}
            >
              Nueva carpeta
            </button>
            {canAdmin ? (
              <button
                className="btn"
                type="button"
                onClick={() => {
                  setDialogError(null);
                  setItemKind("api_key");
                  setMaskSecret(true);
                  openDialog(createRef.current);
                }}
              >
                Nuevo secreto
              </button>
            ) : null}
          </>
        }
      />
      {error ? (
        <p className="alert" role="alert">
          <span>{error}</span>
          <button className="btn-ghost" type="button" onClick={() => void load().catch((cause: unknown) => setError(errorMessage(cause)))}>
            Reintentar
          </button>
        </p>
      ) : null}
      {phase === "loading" ? <p className="empty" role="status">Cargando la bóveda…</p> : null}
      {phase === "ready" ? (
        <div className="workspace">
          <div className="folder-list" role="group" aria-label="Carpetas">
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
                <span className="faint">{entry.githubRepo || entry.access}</span>
              </button>
            ))}
          </div>
          {folder ? (
            <div className="stack">
              <div className="meta">
                <span className="pill">{folder.access}</span>
                {href ? (
                  <a href={href} rel="noopener noreferrer">
                    {folder.githubRepo}
                  </a>
                ) : (
                  <span className="note">{folder.githubRepo || "Sin repo asociado"}</span>
                )}
              </div>
              <div className="tabs" role="tablist" aria-label="Carpeta" onKeyDown={onTabsKeyDown}>
                {tabs.map((entry) => (
                  <button
                    key={entry.id}
                    id={`tab-${entry.id}`}
                    className="tab"
                    type="button"
                    role="tab"
                    aria-selected={tab === entry.id}
                    aria-controls={`panel-${entry.id}`}
                    tabIndex={tab === entry.id ? 0 : -1}
                    disabled={entry.disabled}
                    title={entry.disabled ? "El entorno es para carpetas de proyecto" : undefined}
                    onClick={() => setTab(entry.id)}
                  >
                    {entry.label}
                  </button>
                ))}
              </div>
              {tab === "items" ? (
                <div className="stack" role="tabpanel" id="panel-items" aria-labelledby="tab-items">
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
                          <button className="btn-ghost" type="button" onClick={() => openReveal(entry.id)}>
                            Revelar
                          </button>
                          <button className="btn-danger" type="button" disabled={busy === entry.id} onClick={() => void revoke(entry.id)}>
                            Revocar
                          </button>
                        </div>
                      ) : null}
                    </article>
                  ))}
                </div>
              ) : null}
              {tab === "env" ? (
                <div className="stack" role="tabpanel" id="panel-env" aria-labelledby="tab-env">
                  <div className="callout">
                    <strong>El manifiesto no trae valores.</strong>
                    <p>Cada fila es un nombre de variable. El runner pide este entorno y, después de la aprobación, abre un sobre.</p>
                  </div>
                  {canAdmin && activeItems.length > 0 ? (
                    <form className="panel inline-form" onSubmit={(event) => void onBind(event)}>
                      <h2>Mapear una variable</h2>
                      <label className="field">
                        Elemento
                        <select name="itemId" defaultValue={activeItems[0]?.id}>
                          {activeItems.map((entry) => (
                            <option key={entry.id} value={entry.id}>{entry.name}</option>
                          ))}
                        </select>
                      </label>
                      <label className="field">
                        Variable
                        <input name="envKey" required placeholder="OPENAI_API_KEY" pattern="[A-Z][A-Z0-9_]{0,63}" autoComplete="off" spellCheck={false} />
                      </label>
                      <button className="btn" type="submit" disabled={busy === "bind"}>Mapear</button>
                    </form>
                  ) : null}
                  <div className="panel table-wrap">
                    <table className="data-table">
                      <caption>Variables del entorno. El valor no está en esta lista.</caption>
                      <thead>
                        <tr>
                          <th>Variable</th>
                          <th>Secreto</th>
                          <th>Valor</th>
                          <th>Acción</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(manifest?.entries ?? []).length === 0 ? (
                          <tr>
                            <td colSpan={4} data-label="Estado">Todavía no hay variables.</td>
                          </tr>
                        ) : null}
                        {manifest?.entries.map((entry) => (
                          <tr key={entry.bindingId}>
                            <td className="mono" data-label="Variable">{entry.envKey}</td>
                            <td data-label="Secreto">{entry.itemName}</td>
                            <td data-label="Valor">{entry.revoked ? "revocado" : "oculto"}</td>
                            <td data-label="Acción">
                              {canAdmin ? (
                                <button className="btn-ghost" type="button" disabled={busy === entry.bindingId} onClick={() => void unbind(entry.bindingId)}>
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
                <div className="stack" role="tabpanel" id="panel-access" aria-labelledby="tab-access">
                  <div className="callout">
                    <strong>Compartir no manda el secreto.</strong>
                    <p>Uso permite pedir una inyección. Admin administra la carpeta. Nadie recibe el texto plano en el permiso.</p>
                  </div>
                  {canAdmin ? (
                    <form className="panel inline-form" onSubmit={(event) => void onShare(event)}>
                      <h2>Invitar</h2>
                      <label className="field">
                        Email o id de usuario
                        <input name="grantee" required autoComplete="off" />
                      </label>
                      <label className="field">
                        Permiso
                        <select name="permission" defaultValue="use">
                          <option value="use">uso</option>
                          <option value="admin">admin</option>
                        </select>
                      </label>
                      <button className="btn" type="submit" disabled={busy === "share"}>Compartir</button>
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
                          <div className="tag">{share.permission === "admin" ? "admin" : "uso"}</div>
                        </div>
                        {canAdmin ? (
                          <button className="btn-danger" type="button" disabled={busy === share.id} onClick={() => void removeShare(share.id)}>
                            Quitar
                          </button>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          ) : phase === "ready" ? (
            <p className="empty">Elegí una carpeta para ver sus elementos.</p>
          ) : null}
        </div>
      ) : null}

      <dialog
        ref={folderRef}
        aria-labelledby="folder-dialog-title"
        onClose={(event) => {
          wipeDialog(event.currentTarget);
          setDialogError(null);
          setBusy(null);
        }}
      >
        <form onSubmit={(event) => void onCreateFolder(event)}>
          <h2 id="folder-dialog-title">Carpeta de proyecto</h2>
          <p className="note">El repo es una etiqueta, con el formato owner/repo.</p>
          {dialogError && folderRef.current?.open ? <p className="alert" role="alert">{dialogError}</p> : null}
          <label className="field">
            Nombre
            <input name="name" required maxLength={80} />
          </label>
          <label className="field">
            Repo de GitHub
            <input name="githubRepo" placeholder="owner/repo" autoComplete="off" spellCheck={false} />
          </label>
          <div className="row-actions">
            <button className="btn" type="submit" disabled={busy === "folder"}>Crear carpeta</button>
            <button className="btn-ghost" type="button" onClick={() => closeAndWipe(folderRef.current)}>Cancelar</button>
          </div>
        </form>
      </dialog>

      <dialog
        ref={createRef}
        aria-labelledby="item-dialog-title"
        onClose={(event) => {
          wipeDialog(event.currentTarget);
          setDialogError(null);
          setBusy(null);
          setMaskSecret(true);
          setItemKind("api_key");
        }}
      >
        <form onSubmit={(event) => void onCreateItem(event)}>
          <h2 id="item-dialog-title">Nuevo secreto</h2>
          <p className="note">Se envía una vez para cifrarlo. Después la lista solo guarda nombre y pista.</p>
          {dialogError && createRef.current?.open ? <p className="alert" role="alert">{dialogError}</p> : null}
          <label className="field">
            Nombre
            <input name="name" required maxLength={120} autoComplete="off" />
          </label>
          <label className="field">
            Tipo
            <select
              name="kind"
              value={itemKind}
              onChange={(event) => setItemKind(event.target.value === "ssh_key" ? "ssh_key" : "api_key")}
            >
              <option value="api_key">API key</option>
              <option value="ssh_key">Clave SSH privada</option>
            </select>
          </label>
          <div className="field">
            <label htmlFor="new-secret">Secreto</label>
            <textarea
              id="new-secret"
              name="secret"
              required
              minLength={8}
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              className={maskSecret ? "masked" : undefined}
            />
            <button
              className="btn-ghost"
              type="button"
              aria-pressed={!maskSecret}
              aria-label={maskSecret ? "Mostrar el secreto mientras lo escribo" : "Ocultar el secreto mientras lo escribo"}
              onClick={() => setMaskSecret((current) => !current)}
            >
              {maskSecret ? "Mostrar" : "Ocultar"}
            </button>
            <p className="note">
              {itemKind === "ssh_key"
                ? "Tiene que incluir el bloque PRIVATE KEY. Mínimo 8 caracteres."
                : "Mínimo 8 caracteres. No queda guardado en este navegador."}
            </p>
          </div>
          <label className="field">
            Clave pública SSH, opcional
            <textarea name="publicKey" spellCheck={false} autoComplete="off" placeholder="ssh-ed25519 AAAA... comentario" />
          </label>
          <div className="row-actions">
            <button className="btn" type="submit" disabled={busy === "item"}>Guardar cifrado</button>
            <button className="btn-ghost" type="button" onClick={() => closeAndWipe(createRef.current)}>Cancelar</button>
          </div>
        </form>
      </dialog>

      <dialog
        ref={revealRef}
        aria-labelledby="reveal-dialog-title"
        onClose={(event) => {
          wipeDialog(event.currentTarget);
          ephemeral.clear();
          setDialogError(null);
          setHiddenNote(null);
          setBusy(null);
        }}
      >
        <h2 id="reveal-dialog-title">Revelar una vez</h2>
        <p className="note">El valor queda en esta ventana unos segundos. No está en la lista ni en el registro.</p>
        {dialogError ? <p className="alert" role="alert">{dialogError}</p> : null}
        {ephemeral.secret ? (
          <div className="stack">
            <p>
              Se oculta en {ephemeral.secondsLeft} s.
              {ephemeral.copied ? " Copiado." : ""}
            </p>
            <p className="sr-only" role="status">{ephemeral.copied ? "Secreto copiado." : ""}</p>
            <label className="field" htmlFor="revealed-secret">
              Secreto
              <textarea id="revealed-secret" className="secret-box" readOnly value={ephemeral.secret} spellCheck={false} />
            </label>
            <p className="note">Si lo copiás, el portapapeles lo conserva hasta que copies otra cosa. Esta pantalla lo borra sola.</p>
            <div className="row-actions">
              <button className="btn" type="button" onClick={() => void copySecret()}>
                {ephemeral.copied ? "Copiado" : "Copiar"}
              </button>
              <button className="btn-ghost" type="button" onClick={() => closeAndWipe(revealRef.current)}>
                Ocultar ahora
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={(event) => void unlock(event)}>
            {hiddenNote ? <p className="note" role="status">{hiddenNote}</p> : null}
            <label className="field">
              Elemento
              <select name="itemId" value={revealId ?? ""} onChange={(event) => setRevealId(event.target.value)}>
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
              <button className="btn" type="submit" disabled={busy === "reveal" || activeItems.length === 0}>Mostrar</button>
              <button className="btn-ghost" type="button" onClick={() => closeAndWipe(revealRef.current)}>Cancelar</button>
            </div>
          </form>
        )}
      </dialog>
    </section>
  );
}
