"use client";

import { createContext, useContext, useEffect, useState } from "react";
import { api } from "@/lib/client-api";
import {
  createIdentity,
  decryptSecret,
  decryptWithDek,
  deriveKek,
  encryptSecret,
  exportDek,
  generateSecretKey,
  KDF_ITERATIONS,
  openDek,
  openIdentity,
  randomSalt,
  sealDek,
  sealJson,
  type Envelope,
  type SealedPayload,
} from "@/lib/vault-crypto";

type Profile = {
  kdfSalt: string;
  kdfIterations: number;
  publicKey: string;
  wrappedPrivateKey: string;
  privateKeyIv: string;
  privateKeyTag: string;
};

type VaultContextValue = {
  ready: boolean;
  unlocked: boolean;
  encrypt: (secret: string) => Promise<Envelope>;
  decryptOwned: (envelope: Envelope) => Promise<string>;
  sealFor: (value: unknown, publicKey: string) => Promise<SealedPayload>;
  wrapItemFor: (envelope: Envelope, publicKey: string) => Promise<SealedPayload>;
  openShared: (envelope: Pick<Envelope, "ciphertext" | "iv" | "tag">, seal: SealedPayload) => Promise<string>;
};

const VaultContext = createContext<VaultContextValue | null>(null);

export function useVault() {
  const value = useContext(VaultContext);
  if (!value?.unlocked) throw new Error("Abrí la bóveda con la contraseña y la Secret Key");
  return value;
}

export function useVaultState() {
  return useContext(VaultContext);
}

export function VaultGate({ children }: { children: React.ReactNode }) {
  const [profile, setProfile] = useState<Profile | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [secretKey, setSecretKey] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [session, setSession] = useState<{ kek: CryptoKey; privateKey: CryptoKey } | null>(null);

  useEffect(() => {
    void api<{ profile: Profile | null }>("/api/vault/profile")
      .then((data) => setProfile(data.profile))
      .catch((cause: Error) => {
        setError(cause.message);
        setProfile(null);
      });
  }, []);

  async function setup(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const password = String(form.get("password") ?? "");
    const confirm = String(form.get("confirm") ?? "");
    if (password.length < 12 || password !== confirm) {
      setError("La contraseña de la bóveda necesita 12 caracteres y tiene que coincidir.");
      return;
    }
    const generated = secretKey ?? (await generateSecretKey());
    setSecretKey(generated);
    if (!saved) {
      setError("Confirmá que guardaste la Secret Key. No se puede recuperar.");
      return;
    }
    const kdfSalt = randomSalt();
    const kek = await deriveKek(password, generated, kdfSalt);
    const identity = await createIdentity(kek);
    await api("/api/vault/profile", {
      method: "POST",
      body: JSON.stringify({ ...identity, kdfSalt, kdfIterations: KDF_ITERATIONS }),
    });
    const privateKey = await openIdentity(kek, identity.wrappedPrivateKey, identity.privateKeyIv, identity.privateKeyTag);
    setProfile({ ...identity, kdfSalt, kdfIterations: KDF_ITERATIONS });
    setSession({ kek, privateKey });
    setError(null);
  }

  async function unlock(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!profile) return;
    const form = new FormData(event.currentTarget);
    try {
      const kek = await deriveKek(String(form.get("password") ?? ""), String(form.get("secretKey") ?? ""), profile.kdfSalt);
      const privateKey = await openIdentity(kek, profile.wrappedPrivateKey, profile.privateKeyIv, profile.privateKeyTag);
      setSession({ kek, privateKey });
      setError(null);
    } catch {
      setError("Contraseña o Secret Key incorrecta. El servidor no las guarda.");
    }
  }

  if (profile === undefined) return <p className="note">Cargando la bóveda…</p>;

  if (!profile || !session) {
    return (
      <section className="sheet">
        <h1>{profile ? "Abrir la bóveda" : "Armar la bóveda"}</h1>
        <p className="note">
          La contraseña y la Secret Key se quedan en este navegador. El servidor solo guarda el sobre.
        </p>
        {error ? <p className="alert" role="alert">{error}</p> : null}
        {!profile ? (
          <form onSubmit={(event) => void setup(event)}>
            <label>
              Contraseña de la bóveda
              <input name="password" type="password" minLength={12} required autoComplete="new-password" />
            </label>
            <label>
              Repetir
              <input name="confirm" type="password" minLength={12} required autoComplete="new-password" />
            </label>
            {secretKey ? (
              <>
                <label>
                  Secret Key, guardala ahora
                  <textarea readOnly value={secretKey} />
                </label>
                <label className="check">
                  <input type="checkbox" checked={saved} onChange={(event) => setSaved(event.target.checked)} />
                  La guardé fuera del navegador.
                </label>
              </>
            ) : null}
            <button
              className="btn"
              type="button"
              onClick={() => void generateSecretKey().then(setSecretKey)}
            >
              {secretKey ? "Generar otra" : "Generar Secret Key"}
            </button>
            <button className="btn" type="submit">Crear bóveda</button>
          </form>
        ) : (
          <form onSubmit={(event) => void unlock(event)}>
            <label>
              Contraseña de la bóveda
              <input name="password" type="password" required autoComplete="current-password" />
            </label>
            <label>
              Secret Key
              <input name="secretKey" required autoComplete="off" spellCheck={false} />
            </label>
            <button className="btn" type="submit">Abrir</button>
          </form>
        )}
      </section>
    );
  }

  const value: VaultContextValue = {
    ready: true,
    unlocked: true,
    encrypt: (secret) => encryptSecret(secret, session.kek),
    decryptOwned: (envelope) => decryptSecret(envelope, session.kek),
    sealFor: (payload, publicKey) => sealJson(payload, publicKey),
    wrapItemFor: async (envelope, publicKey) => sealDek(await exportDek(envelope, session.kek), publicKey),
    openShared: async (envelope, seal) => decryptWithDek(envelope, await openDek(seal, session.privateKey)),
  };

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}
