"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/client-api";

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
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api<EventRow[]>("/api/audit")
      .then(setRows)
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "No se pudo completar"));
  }, []);

  return (
    <section>
      <header className="page-head">
        <div>
          <p className="eyebrow">Auditoría</p>
          <h1>Qué se hizo</h1>
          <p className="note">Aprobaciones, revelados y altas. El registro no incluye el material secreto.</p>
        </div>
      </header>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      {rows.length === 0 && !error ? <p className="empty">Todavía no hay eventos.</p> : null}
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
                  <p className="note" style={{ marginTop: 8 }}>
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
