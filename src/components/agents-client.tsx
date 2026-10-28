"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/client-api";

type TokenRow = {
  id: string;
  name: string;
  prefix: string;
  revokedAt: string | null;
  createdAt: string | null;
};

export function AgentsClient() {
  const [rows, setRows] = useState<TokenRow[]>([]);
  const [fresh, setFresh] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setRows(await api<TokenRow[]>("/api/agent/tokens"));
  }

  useEffect(() => {
    void load().catch((cause: Error) => setError(cause.message));
  }, []);

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = String(new FormData(event.currentTarget).get("name") ?? "");
    const created = await api<{ token: string }>("/api/agent/tokens", {
      method: "POST",
      body: JSON.stringify({ name }),
    });
    setFresh(created.token);
    event.currentTarget.reset();
    await load();
  }

  async function revoke(id: string) {
    await api(`/api/agent/tokens/${id}`, { method: "DELETE" });
    await load();
  }

  return (
    <section>
      <h1>Agentes</h1>
      <p className="note">
        El token identifica al agente. No es una credencial de terceros: solo puede pedir uso y canjear un sobre.
        Se muestra una vez.
      </p>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      {fresh ? (
        <p className="panel" style={{ padding: 16 }}>
          <strong>Copialo ahora. No se vuelve a mostrar.</strong>
          <textarea className="mono" readOnly value={fresh} />
          <button className="btn-ghost" type="button" onClick={() => setFresh(null)}>Ocultar</button>
        </p>
      ) : null}
      <form className="toolbar" onSubmit={(event) => void create(event).catch((cause: Error) => setError(cause.message))}>
        <label>
          Nombre del agente
          <input name="name" required maxLength={80} />
        </label>
        <button className="btn" type="submit">Crear token</button>
      </form>
      <div className="table">
        {rows.map((row) => (
          <article key={row.id} className="row">
            <div>
              <strong>{row.name}</strong>
              <div className="note">{row.prefix}…</div>
            </div>
            <div>{row.revokedAt ? "revocado" : "activo"}</div>
            <div className="note">{row.createdAt?.slice(0, 10)}</div>
            {!row.revokedAt ? (
              <button className="btn-danger" type="button" onClick={() => void revoke(row.id).catch((cause: Error) => setError(cause.message))}>
                Revocar
              </button>
            ) : <span />}
          </article>
        ))}
      </div>
    </section>
  );
}
