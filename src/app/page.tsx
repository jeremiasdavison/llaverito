import Link from "next/link";
import { Mark } from "@/components/mark";

export const dynamic = "force-dynamic";

export default function HomePage() {
  return (
    <main className="landing">
      <header className="landing-bar">
        <Mark />
        <nav className="actions" aria-label="Cuenta">
          <Link className="btn-ghost" href="/sign-in">
            Entrar
          </Link>
          <Link className="btn" href="/sign-up">
            Crear cuenta
          </Link>
        </nav>
      </header>
      <section className="hero">
        <p className="eyebrow">Cofre para agentes</p>
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
            Ya tengo cuenta
          </Link>
        </div>
      </section>
      <section className="promise-grid" aria-label="Qué no ve el modelo">
        <article className="card">
          <p className="eyebrow">Chat</p>
          <h2>El modelo no recibe el valor</h2>
          <p>La aprobación confirma el uso. No pega la clave en la respuesta que lee el agente.</p>
        </article>
        <article className="card">
          <p className="eyebrow">Lista</p>
          <h2>La bóveda no lista el secreto</h2>
          <p>Nombre, tipo y una pista. Revelar es otra acción, queda en la auditoría y se oculta solo.</p>
        </article>
        <article className="card">
          <p className="eyebrow">Compartir</p>
          <h2>Un permiso, no un archivo</h2>
          <p>Invitar a una cuenta que ya existe da uso o administración. El permiso no lleva el texto plano.</p>
        </article>
      </section>
      <section className="steps" id="como-funciona" aria-label="Cómo funciona">
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
      <p className="note landing-foot">No hay una cuenta de demostración. La primera vez creás la tuya y cargás tus llaves.</p>
    </main>
  );
}
