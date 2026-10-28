"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { authClient } from "@/lib/auth-client";
import { isStrongPassword } from "@/lib/passwords";

export function AuthForm({ mode, next }: { mode: "sign-in" | "sign-up"; next: string }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");
    setPending(true);
    if (mode === "sign-up") {
      const name = String(form.get("name") ?? "").trim();
      const confirm = String(form.get("confirm") ?? "");
      if (!isStrongPassword(password)) {
        setPending(false);
        setError("Usá al menos 12 caracteres, con letras y números.");
        return;
      }
      if (password !== confirm) {
        setPending(false);
        setError("Las contraseñas no coinciden.");
        return;
      }
      const result = await authClient.signUp.email({ email, password, name, callbackURL: next });
      if (result.error) {
        setPending(false);
        setError(result.error.message ?? "No se pudo crear la cuenta");
        return;
      }
    } else {
      const result = await authClient.signIn.email({ email, password, callbackURL: next });
      if (result.error) {
        setPending(false);
        setError(result.error.message ?? "No se pudo entrar");
        return;
      }
    }
    router.push(next);
    router.refresh();
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
          <input name="password" type="password" autoComplete={mode === "sign-up" ? "new-password" : "current-password"} required minLength={12} maxLength={128} />
        </label>
        {mode === "sign-up" ? (
          <label>
            Repetir contraseña
            <input name="confirm" type="password" autoComplete="new-password" required minLength={12} maxLength={128} />
          </label>
        ) : null}
        <button className="btn" type="submit" disabled={pending}>
          {pending ? "Un momento…" : mode === "sign-up" ? "Crear cuenta" : "Entrar"}
        </button>
        <p className="note">
          {mode === "sign-up" ? (
            <Link href="/sign-in">Ya tengo cuenta</Link>
          ) : (
            <Link href="/sign-up">Crear una cuenta</Link>
          )}
        </p>
      </form>
    </main>
  );
}
