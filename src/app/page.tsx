import Link from "next/link";

export default function HomePage() {
  return (
    <main className="landing">
      <div className="mark">
        <i aria-hidden="true" />
        Llaverito
      </div>
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
        <article className="step">
          <span>01</span>
          <h2>Guardás</h2>
          <p>El material queda cifrado en el servidor. La lista solo muestra nombre y una pista.</p>
        </article>
        <article className="step">
          <span>02</span>
          <h2>Pide</h2>
          <p>El agente abre una solicitud con una clave pública efímera. Vos ves el motivo.</p>
        </article>
        <article className="step">
          <span>03</span>
          <h2>Aprobás</h2>
          <p>La respuesta es un grant corto. El runner lo abre fuera del modelo y lo inyecta.</p>
        </article>
      </section>
    </main>
  );
}
