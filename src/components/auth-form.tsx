"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { authClient, listenForTwoFactor } from "@/lib/auth-client";
import { isStrongPassword, passwordIssues, passwordStrength } from "@/lib/passwords";

type AuthError = { message?: string; code?: string; status?: number };

function signInMessage(error: AuthError) {
  if (error.status === 429) return "Demasiados intentos. Esperá un momento.";
  return "Email o contraseña incorrectos.";
}

function signUpMessage(error: AuthError) {
  if (error.status === 429) return "Demasiados intentos. Esperá un momento.";
  if (error.code === "WEAK_PASSWORD" || error.code === "PASSWORD_COMPROMISED") {
    return error.message ?? "La contraseña no cumple la política.";
  }
  return "No se pudo crear la cuenta. Si ya existe, entrá.";
}

export function AuthForm({ mode, next }: { mode: "sign-in" | "sign-up"; next: string }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [password, setPassword] = useState("");
  const [challenge, setChallenge] = useState(false);
  const strength = passwordStrength(password);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    const currentPassword = String(form.get("password") ?? "");
    setPending(true);
    if (mode === "sign-up") {
      const name = String(form.get("name") ?? "").trim();
      const confirm = String(form.get("confirm") ?? "");
      if (!isStrongPassword(currentPassword)) {
        setPending(false);
        setError(passwordIssues(currentPassword)[0] ?? "La contraseña no cumple la política.");
        return;
      }
      if (currentPassword !== confirm) {
        setPending(false);
        setError("Las contraseñas no coinciden.");
        return;
      }
      const result = await authClient.signUp.email({ email, password: currentPassword, name, callbackURL: next });
      if (result.error) {
        setPending(false);
        setError(signUpMessage(result.error));
        return;
      }
    } else {
      let challenged = false;
      const stop = listenForTwoFactor(() => {
        challenged = true;
      });
      const result = await authClient.signIn.email({ email, password: currentPassword, callbackURL: next });
      stop();
      const redirect = Boolean(result.data && "twoFactorRedirect" in result.data && result.data.twoFactorRedirect);
      if (challenged || redirect) {
        setPending(false);
        setChallenge(true);
        return;
      }
      if (result.error) {
        setPending(false);
        setError(signInMessage(result.error));
        return;
      }
    }
    router.push(next);
    router.refresh();
  }

  async function onCode(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget).get("code") ?? "").trim();
    setPending(true);
    setError(null);
    const result = /^\d{6}$/.test(code)
      ? await authClient.twoFactor.verifyTotp({ code, trustDevice: false })
      : await authClient.twoFactor.verifyBackupCode({ code, trustDevice: false });
    if (result.error) {
      setPending(false);
      setError(result.error.status === 429 ? "Demasiados intentos. Esperá un momento." : "Código incorrecto.");
      return;
    }
    router.push(next);
    router.refresh();
  }

  if (challenge) {
    return (
      <main className="auth-wrap">
        <form className="auth-card" onSubmit={(event) => void onCode(event)}>
          <Link className="mark" href="/">
            <i aria-hidden="true" />
            Llaverito
          </Link>
          <h1>Segundo factor</h1>
          <p className="note">Ingresá el código de 6 dígitos o un código de respaldo. Este dispositivo no queda recordado.</p>
          {error ? <p className="alert" role="alert">{error}</p> : null}
          <label>
            Código
            <input name="code" autoComplete="one-time-code" required spellCheck={false} autoFocus />
          </label>
          <div className="auth-actions">
            <button className="btn" type="submit" disabled={pending}>
              {pending ? "Un momento…" : "Confirmar"}
            </button>
            <button className="btn-ghost" type="button" onClick={() => setChallenge(false)}>
              Volver
            </button>
          </div>
        </form>
      </main>
    );
  }

  return (
    <main className="auth-wrap">
      <form className="auth-card" onSubmit={onSubmit}>
        <Link className="mark" href="/">
          <i aria-hidden="true" />
          Llaverito
        </Link>
        <h1>{mode === "sign-up" ? "Crear cuenta" : "Entrar"}</h1>
        <p className="note">No hay una cuenta de demostración. La primera vez te registrás y cargás tus propias llaves.</p>
        {error ? <p className="alert" role="alert">{error}</p> : null}
        {mode === "sign-up" ? (
          <label>
            Nombre
            <input name="name" autoComplete="name" required minLength={1} maxLength={80} />
          </label>
        ) : null}
        <label>
          Email
          <input name="email" type="email" autoComplete="email" required />
        </label>
        <label>
          Contraseña
          <input
            name="password"
            type="password"
            autoComplete={mode === "sign-up" ? "new-password" : "current-password"}
            required
            minLength={12}
            maxLength={128}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
          />
        </label>
        {mode === "sign-up" ? (
          <>
            <div className="meter" aria-hidden="true">
              <span style={{ width: `${strength.score * 25}%` }} />
            </div>
            <p className="note" role="status">Fortaleza: {strength.label}. 12 caracteres o más, letras y números. Evitá contraseñas filtradas o comunes.</p>
            <label>
              Repetir contraseña
              <input name="confirm" type="password" autoComplete="new-password" required minLength={12} maxLength={128} />
            </label>
          </>
        ) : null}
        <div className="auth-actions">
          <button className="btn" type="submit" disabled={pending}>
            {pending ? "Un momento…" : mode === "sign-up" ? "Crear cuenta" : "Entrar"}
          </button>
          {mode === "sign-up" ? (
            <Link className="btn-ghost" href="/sign-in">
              Ya tengo cuenta
            </Link>
          ) : (
            <Link className="btn-ghost" href="/sign-up">
              Crear cuenta
            </Link>
          )}
        </div>
      </form>
    </main>
  );
}
