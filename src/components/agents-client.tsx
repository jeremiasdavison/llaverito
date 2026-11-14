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

function message(cause: unknown) {
  return cause instanceof Error ? cause.message : "No se pudo completar";
}

export function AgentsClient() {
  const [rows, setRows] = useState<TokenRow[]>([]);
  const [fresh, setFresh] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setRows(await api<TokenRow[]>("/api/agent/tokens"));
  }

  useEffect(() => {
    void load().catch((cause: unknown) => setError(message(cause)));
  }, []);

  async function create(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const name = String(new FormData(event.currentTarget).get("name") ?? "");
    const created = await api<{ token: string }>("/api/agent/tokens", {
      method: "POST",
      body: JSON.stringify({ name }),
    });
    setCopied(false);
    setFresh(created.token);
    event.currentTarget.reset();
    await load();
  }

  async function revoke(id: string) {
    if (!window.confirm("¿Revocar este token? El agente deja de poder pedir.")) return;
    await api(`/api/agent/tokens/${id}`, { method: "DELETE" });
    await load();
  }

  async function copyToken() {
    if (!fresh) return;
    await navigator.clipboard.writeText(fresh);
    setCopied(true);
  }

  return (
    <section>
      <header className="page-head">
        <div>
          <p className="eyebrow">Agentes</p>
          <h1>Quién puede pedir</h1>
          <p className="note">
            El token identifica al runner. Solo puede listar metadatos, abrir solicitudes y canjear un sobre.
            No es una API key de un proveedor.
          </p>
        </div>
      </header>
      <div className="callout">
        <strong>Este token sigue siendo de larga vida.</strong>
        <p>
          Guardalo como secreto del CI, con el nombre LLAVERITO_TOKEN, y no lo pegues en el chat. El reemplazo es un
          OIDC corto de GitHub Actions o GitLab: el job prueba quién es y no deja un llv_ permanente en el repo.
        </p>
      </div>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      {fresh ? (
        <div className="panel stack" style={{ marginTop: 16 }}>
          <strong>Copialo ahora. No se vuelve a mostrar.</strong>
          <textarea className="mono" readOnly value={fresh} spellCheck={false} />
          <div className="row-actions">
            <button className="btn" type="button" onClick={() => void copyToken().catch(() => setCopied(false))}>
              {copied ? "Copiado" : "Copiar token"}
            </button>
            <button className="btn-ghost" type="button" onClick={() => { setFresh(null); setCopied(false); }}>
              Ya lo guardé
            </button>
          </div>
        </div>
      ) : null}
      <form className="toolbar" style={{ marginTop: 16 }} onSubmit={(event) => void create(event).catch((cause: unknown) => setError(message(cause)))}>
        <label>
          Nombre del agente
          <input name="name" required maxLength={80} placeholder="ci del repo" />
        </label>
        <button className="btn" type="submit">Crear token</button>
      </form>
      <div className="stack" style={{ marginTop: 8 }}>
        {rows.length === 0 ? <p className="empty">No hay agentes. Sin token, nadie puede pedir un entorno.</p> : null}
        {rows.map((row) => (
          <article key={row.id} className="panel item">
            <div>
              <h3>{row.name}</h3>
              <div className="meta">
                <span className={row.revokedAt ? "pill bad" : "pill ok"}>{row.revokedAt ? "revocado" : "activo"}</span>
                <span className="mono faint">{row.prefix}…</span>
                <span className="faint">{row.createdAt?.slice(0, 10)}</span>
              </div>
            </div>
            {!row.revokedAt ? (
              <button className="btn-danger" type="button" onClick={() => void revoke(row.id).catch((cause: unknown) => setError(message(cause)))}>
                Revocar
              </button>
            ) : null}
          </article>
        ))}
      </div>
    </section>
  );
}
