"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useId, useRef, useState, type FormEvent } from "react";
import { Mark } from "@/components/mark";
import { authClient, listenForTwoFactor } from "@/lib/auth-client";
import { isStrongPassword, passwordIssues, passwordRules, passwordStrength } from "@/lib/passwords";

type AuthError = { message?: string; code?: string; status?: number };

const RATE_LIMITED = "Demasiados intentos. Esperá un momento y probá de nuevo.";

function isRateLimited(error: AuthError) {
  return error.status === 429 || /too many|rate limit/i.test(error.message ?? "");
}

// En el ingreso no distinguimos "no existe" de "contraseña incorrecta".
function signInMessage(error: AuthError) {
  if (isRateLimited(error)) return RATE_LIMITED;
  return "Email o contraseña incorrectos.";
}

function signUpMessage(error: AuthError) {
  if (isRateLimited(error)) return RATE_LIMITED;
  if (error.code === "WEAK_PASSWORD" || error.code === "PASSWORD_COMPROMISED") {
    return error.message || "La contraseña no cumple la política.";
  }
  return "No se pudo crear la cuenta. Si ya tenés una con ese email, entrá.";
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
  const [challenge, setChallenge] = useState(false);
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
  const strength = passwordStrength(password);
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
      fail("password", passwordIssues(password)[0] ?? "La contraseña no cumple la política.");
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
        if (result.error.code === "WEAK_PASSWORD" || result.error.code === "PASSWORD_COMPROMISED") {
          setInvalid("password");
          setError(signUpMessage(result.error));
          // El input sigue deshabilitado hasta que React re-renderice sin `pending`.
          setTimeout(() => passwordRef.current?.focus(), 0);
        } else {
          setError(signUpMessage(result.error));
        }
        return;
      }
    } else {
      let challenged = false;
      const stop = listenForTwoFactor(() => {
        challenged = true;
      });
      const result = await authClient.signIn.email({
        email: email.trim(),
        password,
        callbackURL: next,
      });
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

  async function onCode(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const code = String(new FormData(event.currentTarget).get("code") ?? "").trim();
    if (code.length === 0) {
      setError("Ingresá el código.");
      return;
    }
    setPending(true);
    setError(null);
    const result = /^\d{6}$/.test(code)
      ? await authClient.twoFactor.verifyTotp({ code, trustDevice: false })
      : await authClient.twoFactor.verifyBackupCode({ code, trustDevice: false });
    if (result.error) {
      setPending(false);
      setError(isRateLimited(result.error) ? RATE_LIMITED : "Código incorrecto.");
      return;
    }
    router.push(next);
    router.refresh();
  }

  const story = (
    <section className="auth-story">
      <div>
        <Mark />
        <h1>{challenge ? "Un paso más." : creating ? "Un cofre para tus llaves." : "Entrá al cofre."}</h1>
        <p className="lede">
          {challenge
            ? "Tu cuenta tiene verificación en dos pasos. Sin el segundo factor, la contraseña sola no abre el cofre."
            : "La contraseña abre tu sesión. No es una clave de proyecto y no se pega en el chat del agente."}
        </p>
      </div>
      <p className="note">No hay una cuenta de demostración. La primera vez te registrás y cargás tus propias llaves.</p>
    </section>
  );

  if (challenge) {
    return (
      <main className="auth-split">
        {story}
        <form className="auth-card" onSubmit={(event) => void onCode(event)} noValidate aria-busy={pending}>
          <Mark />
          <p className="eyebrow">Verificación en dos pasos</p>
          <h1>Segundo factor</h1>
          <p className="note">Ingresá el código de 6 dígitos o un código de respaldo. Este dispositivo no queda recordado.</p>
          {error ? <p className="alert" role="alert">{error}</p> : null}
          <label className="field" htmlFor="code">
            Código
            <input
              id="code"
              name="code"
              autoComplete="one-time-code"
              inputMode="text"
              required
              spellCheck={false}
              autoFocus
              disabled={pending}
              onChange={() => setError(null)}
            />
          </label>
          <button className="btn" type="submit" disabled={pending}>
            {pending ? "Verificando…" : "Confirmar"}
          </button>
          <p className="note auth-switch">
            <button
              className="btn-ghost"
              type="button"
              disabled={pending}
              onClick={() => {
                setChallenge(false);
                setError(null);
              }}
            >
              Volver
            </button>
          </p>
        </form>
      </main>
    );
  }

  return (
    <main className="auth-split">
      {story}
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
            <div id={passwordRulesId}>
              <div className="meter" aria-hidden="true">
                <span style={{ width: `${strength.score * 25}%` }} />
              </div>
              <p className="note" role="status" aria-live="polite">
                Fortaleza: {strength.label}
              </p>
              <ul className="rules">
                {rules.map((rule) => (
                  <li key={rule.id} className={rule.ok ? "rule ok" : "rule"}>
                    <span aria-hidden="true">{rule.ok ? "✓ " : "○ "}</span>
                    {rule.label}
                    <span className="sr-only">{rule.ok ? ", cumplido" : ", pendiente"}</span>
                  </li>
                ))}
              </ul>
              <p className="note">
                Al crear la cuenta también rechazamos contraseñas que incluyan tu email o que hayan aparecido en
                filtraciones conocidas.
              </p>
            </div>
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
                aria-invalid={invalid === "confirm" || confirmMismatch}
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
