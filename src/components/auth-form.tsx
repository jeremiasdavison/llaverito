"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useId, useRef, useState, type FormEvent } from "react";
import { Mark } from "@/components/mark";
import { authClient } from "@/lib/auth-client";
import { isStrongPassword, passwordRules } from "@/lib/passwords";

function translateAuthError(error: { message?: string; code?: string } | null | undefined, fallback: string) {
  const code = error?.code ?? "";
  if (code === "INVALID_EMAIL_OR_PASSWORD") return "Email o contraseña incorrectos.";
  if (code === "USER_ALREADY_EXISTS" || code === "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL") {
    return "Ya hay una cuenta con ese email.";
  }
  if (code === "WEAK_PASSWORD") return "La contraseña necesita 12 caracteres o más, con letras y números.";
  const message = error?.message ?? "";
  if (/invalid email or password/i.test(message)) return "Email o contraseña incorrectos.";
  if (/already exists/i.test(message)) return "Ya hay una cuenta con ese email.";
  if (/too many|rate limit/i.test(message)) return "Demasiados intentos. Esperá un momento y probá de nuevo.";
  return message || fallback;
}

function isEmail(value: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

export function AuthForm({ mode, next }: { mode: "sign-in" | "sign-up"; next: string }) {
  const router = useRouter();
  const creating = mode === "sign-up";
  const passwordRulesId = useId();
  const confirmStatusId = useId();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [invalid, setInvalid] = useState<"name" | "email" | "password" | "confirm" | null>(null);
  const [pending, setPending] = useState(false);
  const nameRef = useRef<HTMLInputElement>(null);
  const emailRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmRef = useRef<HTMLInputElement>(null);

  function fail(field: "name" | "email" | "password" | "confirm", message: string) {
    setInvalid(field);
    setError(message);
    const target = { name: nameRef, email: emailRef, password: passwordRef, confirm: confirmRef }[field];
    target.current?.focus();
  }

  const rules = passwordRules(password);
  const strong = isStrongPassword(password);
  const confirmTouched = confirm.length > 0;
  const confirmMatches = password === confirm;
  const confirmMismatch = confirm.length >= password.length && confirmTouched && !confirmMatches;

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (creating && name.trim().length === 0) {
      fail("name", "Escribí tu nombre.");
      return;
    }
    if (!isEmail(email)) {
      fail("email", "El email no es válido.");
      return;
    }
    if (creating && !strong) {
      fail("password", "Usá al menos 12 caracteres, con letras y números.");
      return;
    }
    if (!creating && password.length === 0) {
      fail("password", "Ingresá tu contraseña.");
      return;
    }
    if (creating && !confirmMatches) {
      fail("confirm", "Las contraseñas no coinciden.");
      return;
    }
    setInvalid(null);
    setPending(true);
    if (creating) {
      const result = await authClient.signUp.email({
        email: email.trim(),
        password,
        name: name.trim(),
        callbackURL: next,
      });
      if (result.error) {
        setPending(false);
        setError(translateAuthError(result.error, "No se pudo crear la cuenta"));
        return;
      }
    } else {
      const result = await authClient.signIn.email({
        email: email.trim(),
        password,
        callbackURL: next,
      });
      if (result.error) {
        setPending(false);
        setError(translateAuthError(result.error, "No se pudo entrar"));
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
          <h1>{creating ? "Un cofre para tus llaves." : "Entrá al cofre."}</h1>
          <p className="lede">
            La contraseña abre tu sesión. No es una clave de proyecto y no se pega en el chat del agente.
          </p>
        </div>
        <p className="note">No hay una cuenta de demostración. La primera vez te registrás y cargás tus propias llaves.</p>
      </section>
      <form className="auth-card" onSubmit={onSubmit} noValidate aria-busy={pending}>
        <Mark />
        <p className="eyebrow">{creating ? "Cuenta nueva" : "Sesión"}</p>
        <h1>{creating ? "Crear cuenta" : "Entrar"}</h1>
        <p className="note">
          {creating
            ? "Elegí una contraseña larga. La vas a ver cumplirse mientras escribís."
            : "No hay una cuenta de demostración."}
        </p>
        {error ? <p className="alert" role="alert">{error}</p> : null}
        {creating ? (
          <label className="field" htmlFor="name">
            Nombre
            <input
              id="name"
              name="name"
              autoComplete="name"
              required
              minLength={1}
              maxLength={80}
              ref={nameRef}
              value={name}
              aria-invalid={invalid === "name"}
              onChange={(event) => {
                setName(event.target.value);
                setError(null);
                setInvalid(null);
              }}
              disabled={pending}
              autoFocus
            />
          </label>
        ) : null}
        <label className="field" htmlFor="email">
          Email
          <input
            id="email"
            name="email"
            type="email"
            autoComplete="email"
            inputMode="email"
            required
            ref={emailRef}
            value={email}
            aria-invalid={invalid === "email"}
            onChange={(event) => {
              setEmail(event.target.value);
              setError(null);
              setInvalid(null);
            }}
            disabled={pending}
            autoFocus={!creating}
          />
        </label>
        <div className="field">
          <label htmlFor="password">Contraseña</label>
          <div className="password-field">
            <input
              id="password"
              name="password"
              type={showPassword ? "text" : "password"}
              autoComplete={creating ? "new-password" : "current-password"}
              required
              maxLength={128}
              ref={passwordRef}
              value={password}
              aria-invalid={invalid === "password"}
              aria-describedby={creating ? passwordRulesId : undefined}
              onChange={(event) => {
                setPassword(event.target.value);
                setError(null);
                setInvalid(null);
              }}
              disabled={pending}
            />
            <button
              className="btn-ghost"
              type="button"
              aria-pressed={showPassword}
              aria-label={showPassword ? "Ocultar contraseña" : "Mostrar contraseña"}
              onClick={() => setShowPassword((current) => !current)}
            >
              {showPassword ? "Ocultar" : "Mostrar"}
            </button>
          </div>
          {creating ? (
            <ul id={passwordRulesId} className="rules">
              {rules.map((rule) => (
                <li key={rule.id} className={rule.ok ? "rule ok" : "rule"}>
                  <span aria-hidden="true">{rule.ok ? "✓ " : "○ "}</span>
                  {rule.label}
                  <span className="sr-only">{rule.ok ? ", cumplido" : ", pendiente"}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </div>
        {creating ? (
          <div className="field">
            <label htmlFor="confirm">Repetir contraseña</label>
            <div className="password-field">
              <input
                id="confirm"
                name="confirm"
                type={showConfirm ? "text" : "password"}
                autoComplete="new-password"
                required
                maxLength={128}
                ref={confirmRef}
                value={confirm}
                aria-invalid={invalid === "confirm" || (confirm.length >= password.length && confirmTouched && !confirmMatches)}
                aria-describedby={confirmStatusId}
                onChange={(event) => {
                  setConfirm(event.target.value);
                  setError(null);
                  setInvalid(null);
                }}
                disabled={pending}
              />
              <button
                className="btn-ghost"
                type="button"
                aria-pressed={showConfirm}
                aria-label={showConfirm ? "Ocultar la repetición" : "Mostrar la repetición"}
                onClick={() => setShowConfirm((current) => !current)}
              >
                {showConfirm ? "Ocultar" : "Mostrar"}
              </button>
            </div>
            <p id={confirmStatusId} className={confirmMismatch ? "rule bad" : confirmMatches && confirmTouched ? "rule ok" : "rule"}>
              {confirmMismatch
                ? "Las contraseñas no coinciden."
                : confirmMatches && confirmTouched
                  ? "Las contraseñas coinciden."
                  : "Tiene que ser igual a la anterior."}
            </p>
          </div>
        ) : null}
        <button className="btn" type="submit" disabled={pending}>
          {pending ? (creating ? "Creando cuenta…" : "Entrando…") : creating ? "Crear cuenta" : "Entrar"}
        </button>
        <p className="note auth-switch">
          {creating ? (
            <>
              ¿Ya tenés cuenta? <Link href="/sign-in">Entrar</Link>
            </>
          ) : (
            <>
              ¿Primera vez? <Link href="/sign-up">Crear cuenta</Link>
            </>
          )}
        </p>
      </form>
    </main>
  );
}
