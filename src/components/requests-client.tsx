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

export function RequestsClient() {
  const [rows, setRows] = useState<RequestRow[]>([]);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [folders, setFolders] = useState<Folder[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

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
    void load().catch((cause: Error) => setError(cause.message));
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
    const result = await api<{ confirmation: string }>(`/api/requests/${id}`, {
      method: "POST",
      body: JSON.stringify({ action }),
    });
    setNotice(result.confirmation);
    await load();
  }

  const projects = folders.filter((folder) => folder.kind === "project");

  return (
    <section>
      <h1>Solicitudes</h1>
      <p className="note">Aprobar devuelve una confirmación y un grant para el agente. El secreto no viaja en esta pantalla.</p>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      {notice ? <p className="note" role="status">{notice}</p> : null}
      <div className="split">
        <div className="stack">
          {rows.length === 0 ? <p className="note">No hay solicitudes.</p> : null}
          {rows.map((row) => (
            <article key={row.id} className="panel" style={{ padding: 16 }}>
              <div className="tag">{row.status} · {row.kind}</div>
              <p>{row.purpose}</p>
              <ul>
                {row.items.map((item) => (
                  <li key={item.id}>{item.name}</li>
                ))}
              </ul>
              {row.confirmation ? <p className="note">{row.confirmation}</p> : null}
              <div className="toolbar">
                {row.canDecide ? (
                  <>
                    <button className="btn" type="button" onClick={() => void decide(row.id, "approve").catch((cause: Error) => setError(cause.message))}>Aprobar</button>
                    <button className="btn-danger" type="button" onClick={() => void decide(row.id, "deny").catch((cause: Error) => setError(cause.message))}>Rechazar</button>
                  </>
                ) : null}
                {row.canCancel ? (
                  <button className="btn-ghost" type="button" onClick={() => void decide(row.id, "deny").catch((cause: Error) => setError(cause.message))}>Cancelar</button>
                ) : null}
              </div>
            </article>
          ))}
        </div>
        <div className="stack">
          <form className="panel" style={{ padding: 16 }} onSubmit={(event) => void createItemRequest(event).catch((cause: Error) => setError(cause.message))}>
            <h2>Pedir elementos</h2>
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
          <form className="panel" style={{ padding: 16 }} onSubmit={(event) => void createEnvRequest(event).catch((cause: Error) => setError(cause.message))}>
            <h2>Pedir el .env del proyecto</h2>
            <label>
              Proyecto
              <select name="folderId" required>
                {projects.map((folder) => (
                  <option key={folder.id} value={folder.id}>{folder.name}</option>
                ))}
              </select>
            </label>
            <label>
              Repo, si la carpeta tiene uno
              <input name="repository" placeholder="owner/repo" />
            </label>
            <label>
              Para qué
              <input name="purpose" required minLength={3} />
            </label>
            <label>
              Clave pública X25519
              <input name="wrapPublicKey" required spellCheck={false} autoComplete="off" />
            </label>
            <button className="btn" type="submit">Pedir inyección</button>
          </form>
        </div>
      </div>
    </section>
  );
}
