"use client";

import { useEffect, useState } from "react";
import { registerStepUpPrompt } from "@/lib/step-up-client";

type Pending = { twoFactor: boolean; resolve: (accepted: boolean) => void };

export function StepUpDialog() {
  const [pending, setPending] = useState<Pending | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    return registerStepUpPrompt(
      (input) =>
        new Promise((resolve) => {
          setError(null);
          setBusy(false);
          setPending({ twoFactor: input.twoFactor, resolve });
        }),
    );
  }, []);

  if (!pending) return null;

  function close(accepted: boolean) {
    pending?.resolve(accepted);
    setPending(null);
    setError(null);
  }

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(null);
    const response = await fetch("/api/session/step-up", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        password: String(form.get("password") ?? ""),
        code: String(form.get("code") ?? ""),
      }),
    });
    const data = (await response.json().catch(() => ({}))) as { error?: string };
    setBusy(false);
    if (!response.ok) {
      setError(data.error ?? "No se pudo confirmar");
      return;
    }
    close(true);
  }

  return (
    <div className="overlay">
      <form
        className="panel"
        role="dialog"
        aria-modal="true"
        aria-labelledby="step-up-title"
        onSubmit={(event) => void onSubmit(event)}
      >
        <h2 id="step-up-title">Confirmar identidad</h2>
        <p className="note">Esta acción entrega o comparte un secreto. La confirmación vale 5 minutos.</p>
        {error ? <p className="alert" role="alert">{error}</p> : null}
        <label>
          Contraseña
          <input name="password" type="password" autoComplete="current-password" required autoFocus />
        </label>
        {pending.twoFactor ? (
          <label>
            Código del autenticador o de respaldo
            <input name="code" autoComplete="one-time-code" required spellCheck={false} />
          </label>
        ) : null}
        <div className="toolbar">
          <button className="btn" type="submit" disabled={busy}>
            {busy ? "Un momento…" : "Confirmar"}
          </button>
          <button className="btn-ghost" type="button" onClick={() => close(false)}>
            Cancelar
          </button>
        </div>
      </form>
    </div>
  );
}
