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
  revokedAt: string | null;
  createdAt: string | null;
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
    const name = String(new FormData(event.currentTarget).get("name") ?? "");
    setBusy(true);
    setCopyError(null);
    try {
      const created = await api<{ token: string }>("/api/agent/tokens", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      token.reveal(created.token);
      event.currentTarget.reset();
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

  return (
    <section aria-busy={phase === "loading"}>
      <PageHeader
        eyebrow="Agentes"
        title="Quién puede pedir"
        lede="El token identifica al runner. Solo puede listar metadatos, abrir solicitudes y canjear un sobre. No es una API key de un proveedor."
      />
      <div className="callout">
        <strong>Este token sigue siendo de larga vida.</strong>
        <p>Guardalo como secreto del CI, con el nombre LLAVERITO_TOKEN, y no lo pegues en el chat. Se muestra una sola vez.</p>
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
                <span className={row.revokedAt ? "pill bad" : "pill ok"}>{row.revokedAt ? "revocado" : "activo"}</span>
                <span className="mono faint">{row.prefix}…</span>
                {row.createdAt ? <time className="faint" dateTime={row.createdAt}>{row.createdAt.slice(0, 10)}</time> : null}
              </div>
            </div>
            {!row.revokedAt ? (
              <button className="btn-danger" type="button" onClick={() => void revoke(row.id)}>
                Revocar
              </button>
            ) : null}
          </article>
        ))}
      </div>
    </section>
  );
}
