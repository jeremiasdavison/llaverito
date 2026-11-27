"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/page-header";
import { api } from "@/lib/client-api";
import { errorMessage } from "@/lib/client-error";

type EventRow = {
  id: string;
  action: string;
  resourceType: string | null;
  createdAt: string;
  metadata: Record<string, string | number | boolean | null>;
};

const labels: Record<string, string> = {
  "folder.create": "Creó una carpeta",
  "folder.update": "Actualizó una carpeta",
  "folder.delete": "Borró una carpeta",
  "item.create": "Guardó un secreto",
  "item.revoke": "Revocó un secreto",
  "item.rotate": "Rotó un secreto",
  "item.unlock": "Reveló un secreto",
  "share.create": "Compartió acceso",
  "share.delete": "Quitó un acceso",
  "env.bind": "Mapeó una variable",
  "env.unbind": "Quitó una variable",
  "request.create": "Creó una solicitud",
  "request.approve": "Aprobó un uso",
  "request.deny": "Rechazó un uso",
  "grant.blocked": "Bloqueó un canje",
  "grant.redeem": "Canjeó un sobre",
  "agent_token.create": "Creó un token de agente",
  "agent_token.revoke": "Revocó un token de agente",
};

export function AuditClient() {
  const [rows, setRows] = useState<EventRow[]>([]);
  const [phase, setPhase] = useState<"loading" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setRows(await api<EventRow[]>("/api/audit"));
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

  return (
    <section aria-busy={phase === "loading"}>
      <PageHeader
        eyebrow="Auditoría"
        title="Qué se hizo"
        lede="Aprobaciones, revelados y altas. El registro no incluye el material secreto."
      />
      {error ? (
        <p className="alert" role="alert">
          <span>{error}</span>
          <button className="btn-ghost" type="button" onClick={() => void load().catch((cause: unknown) => setError(errorMessage(cause)))}>
            Reintentar
          </button>
        </p>
      ) : null}
      {phase === "loading" ? <p className="empty" role="status">Cargando la auditoría…</p> : null}
      {phase === "ready" && rows.length === 0 ? <p className="empty">Todavía no hay eventos.</p> : null}
      <div className="timeline">
        {rows.map((row) => {
          const details = Object.entries(row.metadata).filter(([, value]) => value !== null && value !== "");
          return (
            <article key={row.id} className="panel item">
              <div>
                <h3>{labels[row.action] ?? row.action}</h3>
                <div className="meta">
                  <span className="tag">{row.resourceType ?? "sistema"}</span>
                  <time className="faint" dateTime={row.createdAt}>
                    {new Date(row.createdAt).toLocaleString("es-AR")}
                  </time>
                </div>
                {details.length > 0 ? (
                  <p className="note">
                    {details.map(([key, value]) => `${key}: ${String(value)}`).join(" · ")}
                  </p>
                ) : null}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
