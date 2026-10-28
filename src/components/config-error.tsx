export function ConfigError() {
  return (
    <main className="auth-wrap">
      <section className="auth-card">
        <h1>Falta configurar el cofre</h1>
        <p>
          Llaverito necesita una base Postgres y las claves de servidor. En Vercel hay que definir
          DATABASE_URL, BETTER_AUTH_SECRET y ENCRYPTION_KEY. Los valores no van en el repositorio.
        </p>
      </section>
    </main>
  );
}
