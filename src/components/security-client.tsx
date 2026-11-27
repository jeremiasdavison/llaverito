"use client";

import { useState } from "react";
import { authClient } from "@/lib/auth-client";

function secretFromUri(uri: string) {
  try {
    return new URL(uri).searchParams.get("secret") ?? "";
  } catch {
    return "";
  }
}

export function SecurityClient() {
  const { data: session } = authClient.useSession();
  const enabled = Boolean(session?.user && "twoFactorEnabled" in session.user && session.user.twoFactorEnabled);
  const [error, setError] = useState<string | null>(null);
  const [uri, setUri] = useState<string | null>(null);
  const [backupCodes, setBackupCodes] = useState<string[] | null>(null);
  const [busy, setBusy] = useState(false);

  async function enable(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = String(new FormData(event.currentTarget).get("password") ?? "");
    setBusy(true);
    setError(null);
    const result = await authClient.twoFactor.enable({ password });
    setBusy(false);
    if (result.error || !result.data || !("totpURI" in result.data)) {
      setError(result.error?.message ?? "No se pudo empezar el segundo factor");
      return;
    }
    setUri(result.data.totpURI);
    setBackupCodes(result.data.backupCodes);
  }

  async function confirm(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget).get("code") ?? "").trim();
    setBusy(true);
    setError(null);
    const result = await authClient.twoFactor.verifyTotp({ code, trustDevice: false });
    setBusy(false);
    if (result.error) {
      setError("Código incorrecto. El segundo factor todavía no quedó activo.");
      return;
    }
    setUri(null);
    window.location.assign("/app/security");
  }

  async function disable(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const password = String(new FormData(event.currentTarget).get("password") ?? "");
    setBusy(true);
    setError(null);
    const result = await authClient.twoFactor.disable({ password });
    setBusy(false);
    if (result.error) {
      setError(result.error.message ?? "No se pudo desactivar");
      return;
    }
    window.location.assign("/app/security");
  }

  const secret = uri ? secretFromUri(uri) : "";

  return (
    <section>
      <h1>Seguridad</h1>
      <p className="note">
        Revelar un secreto, aprobar un pedido, compartir o crear un token pide el segundo factor y una confirmación
        reciente. El alta de la cuenta no cambia.
      </p>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      <p className="tag">{enabled ? "segundo factor activo" : "segundo factor apagado"}</p>
      {!enabled && !uri ? (
        <form className="panel" style={{ padding: 16 }} onSubmit={(event) => void enable(event)}>
          <h2>Activar autenticador</h2>
          <label>
            Contraseña actual
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          <button className="btn" type="submit" disabled={busy}>Generar código</button>
        </form>
      ) : null}
      {uri ? (
        <form className="panel stack" style={{ padding: 16 }} onSubmit={(event) => void confirm(event)}>
          <h2>Cargalo en la app</h2>
          <p className="note">Pegá la URI o el secreto en el autenticador. No uses un generador de QR externo.</p>
          <textarea className="mono" readOnly value={uri} />
          {secret ? <p className="mono">Secreto: {secret}</p> : null}
          {backupCodes ? (
            <div>
              <p className="note">Códigos de respaldo. Se muestran una sola vez.</p>
              <ul>
                {backupCodes.map((code) => (
                  <li key={code} className="mono">{code}</li>
                ))}
              </ul>
            </div>
          ) : null}
          <label>
            Código de 6 dígitos
            <input name="code" inputMode="numeric" autoComplete="one-time-code" required pattern="[0-9]{6}" />
          </label>
          <button className="btn" type="submit" disabled={busy}>Activar</button>
        </form>
      ) : null}
      {enabled ? (
        <form className="panel" style={{ padding: 16 }} onSubmit={(event) => void disable(event)}>
          <h2>Desactivar</h2>
          <label>
            Contraseña actual
            <input name="password" type="password" autoComplete="current-password" required />
          </label>
          <button className="btn-danger" type="submit" disabled={busy}>Desactivar segundo factor</button>
        </form>
      ) : null}
    </section>
  );
}
