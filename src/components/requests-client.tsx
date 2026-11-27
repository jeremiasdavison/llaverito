"use client";

import { useEffect, useState, type FormEvent } from "react";
import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/client-api";
import { errorMessage } from "@/lib/client-error";

type VaultItem = { id: string; name: string; revokedAt: string | null; folderId: string };
type Folder = { id: string; name: string; kind: "personal" | "project" };
type RequestRow = {
  id: string;
  purpose: string;
  kind: string;
  status: string;
  canDecide: boolean;
  canCancel: boolean;
  confirmation: string | null;
  items: { id: string; name: string; kind: string }[];
};

const statusLabel: Record<string, string> = {
  pending: "pendiente",
  approved: "aprobada",
  denied: "rechazada",
  expired: "vencida",
  cancelled: "cancelada",
  canceled: "cancelada",
  redeemed: "canjeada",
};

export function RequestsClient() {
  const [rows, setRows] = useState<RequestRow[]>([]);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function load() {
    const [requests, vault] = await Promise.all([
      api<RequestRow[]>("/api/requests"),
      api<{ items: VaultItem[]; folders: Folder[] }>("/api/vault"),
    ]);
    setRows(requests);
    setItems(vault.items);
    setFolders(vault.folders);
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

  async function createItemRequest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const selected = form.getAll("itemId").map(String);
    if (selected.length === 0) {
      setError("Elegí al menos un elemento.");
      return;
    }
    setBusy("items");
    try {
      const result = await api<{ confirmation: string }>("/api/requests", {
        method: "POST",
        body: JSON.stringify({
          itemIds: selected,
          purpose: String(form.get("purpose") ?? ""),
          wrapPublicKey: String(form.get("wrapPublicKey") ?? ""),
        }),
      });
      setNotice(result.confirmation);
      setError(null);
      event.currentTarget.reset();
      await load();
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function createEnvRequest(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const folderId = String(form.get("folderId") ?? "");
    setBusy("env");
    try {
      const result = await api<{ confirmation: string }>(`/api/folders/${folderId}/env/request`, {
        method: "POST",
        body: JSON.stringify({
          purpose: String(form.get("purpose") ?? ""),
          wrapPublicKey: String(form.get("wrapPublicKey") ?? ""),
          repository: String(form.get("repository") ?? ""),
        }),
      });
      setNotice(result.confirmation);
      setError(null);
      await load();
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  async function decide(id: string, action: "approve" | "deny") {
    setBusy(id);
    try {
      const result = await api<{ confirmation: string }>(`/api/requests/${id}`, {
        method: "POST",
        body: JSON.stringify({ action }),
      });
      setNotice(result.confirmation);
      setError(null);
      await load();
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(null);
    }
  }

  const projects = folders.filter((entry) => entry.kind === "project");
  const waiting = rows.filter((row) => row.canDecide).length;
  const activeItems = items.filter((item) => !item.revokedAt);

  return (
    <section aria-busy={phase === "loading"}>
      <PageHeader
        eyebrow="Solicitudes"
        title="Aprobar un uso"
        lede={`Aprobar arma un grant para el runner. Esta pantalla no muestra el secreto ni el sobre.${waiting > 0 ? ` Hay ${waiting} esperando decisión.` : ""}`}
      />
      {error ? (
        <p className="alert" role="alert">
          <span>{error}</span>
          <button className="btn-ghost" type="button" onClick={() => void load().catch((cause: unknown) => setError(errorMessage(cause)))}>
            Reintentar
          </button>
        </p>
      ) : null}
      {notice ? <p className="callout" role="status">{notice}</p> : null}
      {phase === "loading" ? <p className="empty" role="status">Cargando solicitudes…</p> : null}
      {phase === "ready" ? (
        <div className="split request-layout">
          <div className="queue">
            {rows.length === 0 ? (
              <p className="empty">No hay solicitudes. Un agente las crea desde el runner, con una clave pública que él mismo generó.</p>
            ) : null}
            {rows.map((row) => (
              <article key={row.id} className="panel request-card">
                <div className="meta">
                  <span className={row.status === "pending" ? "pill" : row.status === "denied" || row.status === "expired" ? "pill bad" : "pill ok"}>
                    {statusLabel[row.status] ?? row.status}
                  </span>
                  <span className="tag">{row.kind}</span>
                </div>
                <h2>{row.purpose}</h2>
                {row.items.length > 0 ? (
                  <ul>
                    {row.items.map((item) => (
                      <li key={item.id}>{item.name}</li>
                    ))}
                  </ul>
                ) : null}
                {row.confirmation ? <p className="note">{row.confirmation}</p> : null}
                <div className="toolbar">
                  {row.canDecide ? (
                    <>
                      <button className="btn" type="button" disabled={busy === row.id} onClick={() => void decide(row.id, "approve")}>
                        Aprobar
                      </button>
                      <button className="btn-danger" type="button" disabled={busy === row.id} onClick={() => void decide(row.id, "deny")}>
                        Rechazar
                      </button>
                    </>
                  ) : null}
                  {row.canCancel ? (
                    <button className="btn-ghost" type="button" disabled={busy === row.id} onClick={() => void decide(row.id, "deny")}>
                      Cancelar
                    </button>
                  ) : null}
                </div>
              </article>
            ))}
          </div>
          <div className="stack">
            <form className="panel" onSubmit={(event) => void createItemRequest(event)}>
              <h2>Pedir elementos</h2>
              <p className="note">Pegá solo la clave pública X25519 del runner. La privada se queda en esa máquina.</p>
              <label className="field">
                Para qué
                <input name="purpose" required minLength={3} maxLength={500} />
              </label>
              <label className="field">
                Clave pública X25519 (base64url, 32 bytes)
                <input name="wrapPublicKey" required spellCheck={false} autoComplete="off" />
              </label>
              <fieldset>
                <legend>Elementos</legend>
                {activeItems.length === 0 ? <p className="note">No hay elementos activos.</p> : null}
                {activeItems.map((item) => (
                  <label key={item.id} className="check">
                    <input type="checkbox" name="itemId" value={item.id} />
                    {item.name}
                  </label>
                ))}
              </fieldset>
              <button className="btn" type="submit" disabled={busy === "items" || activeItems.length === 0}>
                {busy === "items" ? "Creando…" : "Crear solicitud"}
              </button>
            </form>
            <form className="panel" onSubmit={(event) => void createEnvRequest(event)}>
              <h2>Pedir el entorno del proyecto</h2>
              <p className="note">El pedido nombra el repo. No adjunta un archivo .env.</p>
              <label className="field">
                Proyecto
                <select name="folderId" required defaultValue={projects[0]?.id ?? ""}>
                  {projects.length === 0 ? <option value="">No hay carpetas de proyecto</option> : null}
                  {projects.map((entry) => (
                    <option key={entry.id} value={entry.id}>{entry.name}</option>
                  ))}
                </select>
              </label>
              <label className="field">
                Repo, si la carpeta tiene uno
                <input name="repository" placeholder="owner/repo" autoComplete="off" spellCheck={false} />
              </label>
              <label className="field">
                Para qué
                <input name="purpose" required minLength={3} />
              </label>
              <label className="field">
                Clave pública X25519
                <input name="wrapPublicKey" required spellCheck={false} autoComplete="off" />
              </label>
              <button className="btn" type="submit" disabled={busy === "env" || projects.length === 0}>
                {busy === "env" ? "Pidiendo…" : "Pedir inyección"}
              </button>
            </form>
          </div>
        </div>
      ) : null}
    </section>
  );
}
