"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { Mark } from "@/components/mark";
import { authClient } from "@/lib/auth-client";
import { isStrongPassword } from "@/lib/passwords";

export function AuthForm({ mode, next }: { mode: "sign-in" | "sign-up"; next: string }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const creating = mode === "sign-up";

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");
    setPending(true);
    if (creating) {
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
    <main className="auth-split">
      <section className="auth-story">
        <div>
          <Mark />
          <h1>{creating ? "Un cofre por persona. Ningún .env de muestra." : "Entrá al cofre."}</h1>
          <p className="lede">
            La contraseña abre tu sesión. No es una clave de proyecto y no se pega en el chat del agente.
          </p>
        </div>
        <p className="note">
          En el deploy de producción, entrar con GitHub sigue apagado hasta que existan
          {" "}LLAVERITO_GITHUB_CLIENT_ID y LLAVERITO_GITHUB_CLIENT_SECRET. Esta versión usa email.
        </p>
      </section>
      <form className="auth-card" onSubmit={onSubmit}>
        <p className="eyebrow">{creating ? "Cuenta nueva" : "Sesión"}</p>
        <h1>{creating ? "Crear cuenta" : "Entrar"}</h1>
        {error ? <p className="alert" role="alert">{error}</p> : null}
        {creating ? (
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
            autoComplete={creating ? "new-password" : "current-password"}
            required
            minLength={12}
            maxLength={128}
          />
        </label>
        {creating ? (
          <label>
            Repetir contraseña
            <input name="confirm" type="password" autoComplete="new-password" required minLength={12} maxLength={128} />
          </label>
        ) : null}
        <button className="btn" type="submit" disabled={pending}>
          {pending ? "Un momento…" : creating ? "Crear cuenta" : "Entrar"}
        </button>
        <p className="note">
          {creating ? <Link href="/sign-in">Ya tengo cuenta</Link> : <Link href="/sign-up">Crear una cuenta</Link>}
        </p>
      </form>
    </main>
  );
}
