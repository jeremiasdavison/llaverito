"use client";

import { useEffect, useState, type FormEvent } from "react";
import { PageHeader } from "@/components/page-header";
import { useEphemeralSecret } from "@/components/use-ephemeral-secret";
import { api } from "@/lib/client-api";
import { errorMessage } from "@/lib/client-error";

type TokenRow = {
  id: string;
  name: string;
  prefix: string;
  scopes: string[];
  revokedAt: string | null;
  createdAt: string | null;
  expiresAt: string | null;
  expired: boolean;
};

export function AgentsClient() {
  const [rows, setRows] = useState<TokenRow[]>([]);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [copyError, setCopyError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const token = useEphemeralSecret();

  async function load() {
    setRows(await api<TokenRow[]>("/api/agent/tokens"));
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

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name") ?? "");
    setBusy(true);
    setCopyError(null);
    try {
      const created = await api<{ token: string }>("/api/agent/tokens", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      token.reveal(created.token);
      form.reset();
      await load();
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (!window.confirm("¿Revocar este token? El agente deja de poder pedir.")) return;
    try {
      await api(`/api/agent/tokens/${id}`, { method: "DELETE" });
      await load();
    } catch (cause) {
      setError(errorMessage(cause));
    }
  }

  async function copyToken() {
    try {
      await token.copy();
      setCopyError(null);
    } catch {
      setCopyError("No se pudo copiar. Seleccioná el texto y copialo a mano.");
    }
  }

  async function rotate(id: string) {
    if (!window.confirm("¿Rotar este token? El anterior deja de funcionar ahora y tenés que actualizar el secreto del CI.")) return;
    setCopyError(null);
    try {
      const created = await api<{ token: string }>(`/api/agent/tokens/${id}/rotate`, {
        method: "POST",
        body: JSON.stringify({}),
      });
      token.reveal(created.token);
      await load();
    } catch (cause) {
      setError(errorMessage(cause));
    }
  }

  function status(row: TokenRow) {
    if (row.revokedAt) return { label: "revocado", tone: "pill bad" };
    if (row.expired) return { label: "vencido", tone: "pill bad" };
    return { label: "activo", tone: "pill ok" };
  }

  return (
    <section aria-busy={phase === "loading"}>
      <PageHeader
        eyebrow="Agentes"
        title="Quién puede pedir"
        lede="El token identifica al runner. Solo puede listar metadatos, abrir solicitudes y canjear un sobre. No es una API key de un proveedor."
      />
      <div className="callout">
        <strong>El token vence a los 90 días y se muestra una sola vez.</strong>
        <p>
          Guardalo como secreto del CI, con el nombre LLAVERITO_TOKEN, y no lo pegues en el chat. Rotarlo emite uno nuevo
          e invalida el anterior al instante; revocarlo lo corta sin reemplazo.
        </p>
      </div>
      {error ? (
        <p className="alert" role="alert">
          <span>{error}</span>
          <button className="btn-ghost" type="button" onClick={() => void load().catch((cause: unknown) => setError(errorMessage(cause)))}>
            Reintentar
          </button>
        </p>
      ) : null}
      {token.secret ? (
        <div className="panel stack token-once">
          <strong>Copialo ahora. No se vuelve a mostrar.</strong>
          <p>
            Se oculta en {token.secondsLeft} s.
            {token.copied ? " Copiado." : ""}
          </p>
          <p className="sr-only" role="status">{token.copied ? "Token copiado." : ""}</p>
          <textarea className="mono" readOnly value={token.secret} spellCheck={false} aria-label="Token del agente" />
          <p className="note">Si lo copiás, el portapapeles lo conserva hasta que copies otra cosa.</p>
          {copyError ? <p className="alert" role="alert">{copyError}</p> : null}
          <div className="row-actions">
            <button className="btn" type="button" onClick={() => void copyToken()}>
              {token.copied ? "Copiado" : "Copiar token"}
            </button>
            <button className="btn-ghost" type="button" onClick={() => token.clear()}>
              Ya lo guardé
            </button>
          </div>
        </div>
      ) : null}
      <form className="toolbar" onSubmit={(event) => void create(event)}>
        <label className="field">
          Nombre del agente
          <input name="name" required maxLength={80} placeholder="ci del repo" autoComplete="off" />
        </label>
        <button className="btn" type="submit" disabled={busy}>{busy ? "Creando…" : "Crear token"}</button>
      </form>
      {phase === "loading" ? <p className="empty" role="status">Cargando agentes…</p> : null}
      {phase === "ready" && rows.length === 0 ? <p className="empty">No hay agentes. Sin token, nadie puede pedir un entorno.</p> : null}
      <div className="stack">
        {rows.map((row) => (
          <article key={row.id} className="panel item">
            <div>
              <h3>{row.name}</h3>
              <div className="meta">
                <span className={status(row).tone}>{status(row).label}</span>
                <span className="mono faint">{row.prefix}…</span>
                {row.scopes.map((scope) => (
                  <span key={scope} className="tag">{scope}</span>
                ))}
                {row.createdAt ? (
                  <span className="faint">
                    creado <time dateTime={row.createdAt}>{row.createdAt.slice(0, 10)}</time>
                  </span>
                ) : null}
                {row.expiresAt ? (
                  <span className="faint">
                    {row.expired ? "venció" : "vence"} <time dateTime={row.expiresAt}>{row.expiresAt.slice(0, 10)}</time>
                  </span>
                ) : null}
              </div>
            </div>
            {!row.revokedAt ? (
              <div className="row-actions">
                <button className="btn-ghost" type="button" onClick={() => void rotate(row.id)}>
                  Rotar
                </button>
                <button className="btn-danger" type="button" onClick={() => void revoke(row.id)}>
                  Revocar
                </button>
              </div>
            ) : null}
          </article>
        ))}
      </div>
    </section>
  );
}
