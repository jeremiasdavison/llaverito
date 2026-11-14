export function ConfigError() {
  return (
    <main className="auth-wrap">
      <section className="auth-card">
        <p className="eyebrow">vaultAgent</p>
        <h1>Falta configurar el cofre</h1>
        <p>
          Esta versión necesita Postgres y las claves de servidor. En Vercel hay que definir
          DATABASE_URL, BETTER_AUTH_SECRET y ENCRYPTION_KEY. Esos valores no van en el repositorio
          ni en el chat.
        </p>
      </section>
    </main>
  );
}
