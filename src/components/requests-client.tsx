"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/client-api";

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

function message(cause: unknown) {
  return cause instanceof Error ? cause.message : "No se pudo completar";
}

const statusLabel: Record<string, string> = {
  pending: "pendiente",
  approved: "aprobada",
  denied: "rechazada",
  cancelled: "cancelada",
  canceled: "cancelada",
  redeemed: "canjeada",
};

export function RequestsClient() {
  const [rows, setRows] = useState<RequestRow[]>([]);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [folders, setFolders] = useState<Folder[]>([]);
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
  }

  useEffect(() => {
    void load().catch((cause: unknown) => setError(message(cause)));
  }, []);

  async function createItemRequest(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const selected = form.getAll("itemId").map(String);
    const result = await api<{ confirmation: string }>("/api/requests", {
      method: "POST",
      body: JSON.stringify({
        itemIds: selected,
        purpose: String(form.get("purpose") ?? ""),
        wrapPublicKey: String(form.get("wrapPublicKey") ?? ""),
      }),
    });
    setNotice(result.confirmation);
    event.currentTarget.reset();
    await load();
  }

  async function createEnvRequest(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const folderId = String(form.get("folderId") ?? "");
    const result = await api<{ confirmation: string }>(`/api/folders/${folderId}/env/request`, {
      method: "POST",
      body: JSON.stringify({
        purpose: String(form.get("purpose") ?? ""),
        wrapPublicKey: String(form.get("wrapPublicKey") ?? ""),
        repository: String(form.get("repository") ?? ""),
      }),
    });
    setNotice(result.confirmation);
    await load();
  }

  async function decide(id: string, action: "approve" | "deny") {
    setBusy(id);
    try {
      const result = await api<{ confirmation: string }>(`/api/requests/${id}`, {
        method: "POST",
        body: JSON.stringify({ action }),
      });
      setNotice(result.confirmation);
      await load();
    } catch (cause) {
      setError(message(cause));
    } finally {
      setBusy(null);
    }
  }

  const projects = folders.filter((folder) => folder.kind === "project");
  const waiting = rows.filter((row) => row.canDecide).length;

  return (
    <section>
      <header className="page-head">
        <div>
          <p className="eyebrow">Solicitudes</p>
          <h1>Aprobar un uso</h1>
          <p className="note">
            Aprobar arma un grant para el runner. Esta pantalla no muestra el secreto ni el sobre.
            {waiting > 0 ? ` Hay ${waiting} esperando decisión.` : ""}
          </p>
        </div>
      </header>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      {notice ? <p className="callout" role="status">{notice}</p> : null}
      <div className="split request-layout">
        <div className="queue">
          {rows.length === 0 ? (
            <p className="empty">No hay solicitudes. Un agente las crea desde el runner, con una clave pública que él mismo generó.</p>
          ) : null}
          {rows.map((row) => (
            <article key={row.id} className="panel request-card">
              <div className="meta">
                <span className={row.status === "pending" ? "pill" : "pill ok"}>{statusLabel[row.status] ?? row.status}</span>
                <span className="tag">{row.kind}</span>
              </div>
              <h2>{row.purpose}</h2>
              <ul>
                {row.items.map((item) => (
                  <li key={item.id}>{item.name}</li>
                ))}
              </ul>
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
          <form className="panel" onSubmit={(event) => void createItemRequest(event).catch((cause: unknown) => setError(message(cause)))}>
            <h2>Pedir elementos</h2>
            <p className="note">
              Pegá solo la clave pública X25519 del runner. La privada se queda en esa máquina y no entra en este formulario.
            </p>
            <label>
              Para qué
              <input name="purpose" required minLength={3} maxLength={500} />
            </label>
            <label>
              Clave pública X25519 (base64url, 32 bytes)
              <input name="wrapPublicKey" required spellCheck={false} autoComplete="off" />
            </label>
            <fieldset>
              <legend>Elementos</legend>
              {items.filter((item) => !item.revokedAt).map((item) => (
                <label key={item.id} className="check">
                  <input type="checkbox" name="itemId" value={item.id} />
                  {item.name}
                </label>
              ))}
            </fieldset>
            <button className="btn" type="submit">Crear solicitud</button>
          </form>
          <form className="panel" onSubmit={(event) => void createEnvRequest(event).catch((cause: unknown) => setError(message(cause)))}>
            <h2>Pedir el entorno del proyecto</h2>
            <p className="note">El pedido nombra el repo. No adjunta un archivo .env.</p>
            <label>
              Proyecto
              <select name="folderId" required>
                {projects.length === 0 ? <option value="">No hay carpetas de proyecto</option> : null}
                {projects.map((folder) => (
                  <option key={folder.id} value={folder.id}>{folder.name}</option>
                ))}
              </select>
            </label>
            <label>
              Repo, si la carpeta tiene uno
              <input name="repository" placeholder="owner/repo" autoComplete="off" />
            </label>
            <label>
              Para qué
              <input name="purpose" required minLength={3} />
            </label>
            <label>
              Clave pública X25519
              <input name="wrapPublicKey" required spellCheck={false} autoComplete="off" />
            </label>
            <button className="btn" type="submit" disabled={projects.length === 0}>Pedir inyección</button>
          </form>
        </div>
      </div>
    </section>
  );
}
