"use client";

import { useEffect, useState } from "react";
import { authClient } from "@/lib/auth-client";
import { api } from "@/lib/client-api";

type Repo = { fullName: string; private: boolean };
type VaultItem = { id: string; name: string; kind: string; githubRepos?: string[] };

export default function GithubPage() {
  const [connected, setConnected] = useState(false);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  async function load() {
    const [github, vault] = await Promise.all([
      api<{ connected: boolean; repos: Repo[] }>("/api/github/repos"),
      api<{ items: VaultItem[] }>("/api/vault"),
    ]);
    setConnected(github.connected);
    setRepos(github.repos);
    setItems(vault.items);
  }

  useEffect(() => {
    void load().catch((cause: Error) => setError(cause.message));
  }, []);

  async function link(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    await api(`/api/items/${String(form.get("itemId"))}/repos`, {
      method: "POST",
      body: JSON.stringify({ githubRepo: String(form.get("githubRepo") ?? "") }),
    });
    setNotice("Repositorio vinculado. La clave sigue cifrada.");
    await load();
  }

  return (
    <section>
      <h1>GitHub</h1>
      <p className="note">
        El login identifica la cuenta. Acá vinculás un repositorio a una clave SSH o a un token. El secreto no viaja a GitHub ni vuelve en claro.
      </p>
      {error ? <p className="alert" role="alert">{error}</p> : null}
      {notice ? <p className="note">{notice}</p> : null}
      {!connected ? (
        <button className="btn" type="button" onClick={() => void authClient.linkSocial({ provider: "github", callbackURL: "/app/github" })}>
          Conectar GitHub
        </button>
      ) : (
        <p className="note">{repos.length} repositorios visibles con tu cuenta.</p>
      )}
      <form className="panel" onSubmit={(event) => void link(event).catch((cause: Error) => setError(cause.message))}>
        <h2>Vincular repo y secreto</h2>
        <label>
          Secreto
          <select name="itemId" required>
            {items.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name} ({item.kind === "ssh_key" ? "SSH" : "token"}) {item.githubRepos?.join(", ")}
              </option>
            ))}
          </select>
        </label>
        <label>
          Repositorio
          <input name="githubRepo" list="repos" required placeholder="owner/repo" />
          <datalist id="repos">
            {repos.map((repo) => (
              <option key={repo.fullName} value={repo.fullName} />
            ))}
          </datalist>
        </label>
        <button className="btn" type="submit">Vincular</button>
      </form>
    </section>
  );
}