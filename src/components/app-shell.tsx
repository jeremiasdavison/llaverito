"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { authClient } from "@/lib/auth-client";

const links = [
  { href: "/app", label: "Bóveda" },
  { href: "/app/requests", label: "Solicitudes" },
  { href: "/app/agents", label: "Agentes" },
  { href: "/app/audit", label: "Auditoría" },
];

export function AppShell({
  name,
  email,
  children,
}: {
  name: string;
  email: string;
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();

  async function signOut() {
    await authClient.signOut();
    router.push("/");
    router.refresh();
  }

  return (
    <div className="shell">
      <aside className="rail">
        <Link className="mark" href="/app">
          <i aria-hidden="true" />
          Llaverito
        </Link>
        <nav aria-label="Secciones">
          {links.map((link) => (
            <Link key={link.href} href={link.href} aria-current={pathname === link.href ? "page" : undefined}>
              {link.label}
            </Link>
          ))}
        </nav>
        <div className="who">
          <div>{name}</div>
          <div>{email}</div>
          <button className="signout" type="button" onClick={() => void signOut()}>
            Salir
          </button>
        </div>
      </aside>
      <div className="main">{children}</div>
    </div>
  );
}
