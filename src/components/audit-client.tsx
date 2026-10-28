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

export function AuditClient() {
  const [rows, setRows] = useState<EventRow[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api<EventRow[]>("/api/audit")
      .then(setRows)
      .catch((cause: Error) => setError(cause.message));
  }, []);

  return (
    <section>
      <h1>Auditoría</h1>
      <p className="note">Aprobaciones, revelados y altas. Sin material secreto.</p>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      <div className="table">
        {rows.map((row) => (
          <article key={row.id} className="row">
            <strong>{row.action}</strong>
            <span>{row.resourceType}</span>
            <span className="note">{new Date(row.createdAt).toLocaleString("es-AR")}</span>
            <span className="note">{Object.entries(row.metadata).map(([key, value]) => `${key}: ${value}`).join(" · ")}</span>
          </article>
        ))}
      </div>
    </section>
  );
}
