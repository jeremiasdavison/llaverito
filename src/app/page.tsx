import Link from "next/link";
import { Mark } from "@/components/mark";

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
        <p className="eyebrow">Para quien arma proyectos con un agente</p>
        <h1>El .env deja de viajar por mail y por Teams.</h1>
        <p className="lede">
          vaultAgent guarda API keys y claves SSH cifradas. La lista muestra el nombre y una pista.
          Cuando un agente necesita el entorno, una persona aprueba y el runner abre un sobre de un
          solo uso fuera del modelo.
        </p>
        <div className="actions">
          <Link className="btn" href="/sign-up">
            Crear el cofre
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
          <p>Nombre, tipo y pista. Revelar es otra acción, queda en la auditoría y se cierra en esa pantalla.</p>
        </article>
        <article className="card">
          <p className="eyebrow">Compartir</p>
          <h2>Un permiso, no un archivo</h2>
          <p>Invitar por email da uso o administración. El mensaje no lleva el texto plano.</p>
        </article>
      </section>
      <section className="steps" aria-label="Cómo funciona hoy">
        <article className="step">
          <span>01</span>
          <h2>Guardás</h2>
          <p>El material entra por un formulario y se cifra. La pantalla de la carpeta no lo vuelve a pedir a la lista.</p>
        </article>
        <article className="step">
          <span>02</span>
          <h2>Pide</h2>
          <p>El runner arma una clave pública efímera y una solicitud con el motivo. La privada no se pega en el chat.</p>
        </article>
        <article className="step">
          <span>03</span>
          <h2>Aprobás</h2>
          <p>El canje dura dos minutos y sirve una vez. El runner lo abre y lo inyecta en el proceso.</p>
        </article>
      </section>
      <section className="panel path">
        <p className="eyebrow">Siguiente, todavía no está en esta versión</p>
        <h2>El entorno del repo, para quien el dueño deja entrar</h2>
        <ol>
          <li>El dueño ata la carpeta a un repositorio de GitHub o GitLab y permite el entorno.</li>
          <li>La app pregunta al host si esa persona sigue teniendo acceso.</li>
          <li>Si sí, recibe un sobre cerrado con su clave pública. La base guarda cifrado.</li>
          <li>Si pierde el repo, ese sobre se revoca. Más adelante el mismo entorno se puede empujar a Vercel.</li>
        </ol>
      </section>
    </main>
  );
}
