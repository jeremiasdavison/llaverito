import Link from "next/link";

export default function HomePage() {
  return (
    <main className="landing">
      <Link className="mark" href="/">
        vaultAgent
      </Link>
      <section className="hero">
        <h1>Las llaves las usa el agente. El secreto se queda en el cofre.</h1>
        <p className="lede">
          Guardá API keys y claves SSH cifradas. Cuando un agente las necesite, vos aprobás.
          Lo que vuelve es un grant de un solo uso, no el secreto.
        </p>
        <div className="actions">
          <Link className="btn" href="/sign-up">
            Crear cuenta
          </Link>
          <Link className="btn-ghost" href="/sign-in">
            Entrar
          </Link>
        </div>
      </section>
      <section className="steps" aria-label="Cómo funciona">
        <article className="step glass">
          <h2>Guardás</h2>
          <p>La llave se cifra en este navegador. La lista muestra el nombre y una pista.</p>
        </article>
        <article className="step glass">
          <h2>Pide</h2>
          <p>El agente abre una solicitud. Vos ves para qué la quiere.</p>
        </article>
        <article className="step glass">
          <h2>Aprobás</h2>
          <p>Vuelve un sobre de un solo uso. El secreto no entra en la respuesta.</p>
        </article>
      </section>
    </main>
  );
}
