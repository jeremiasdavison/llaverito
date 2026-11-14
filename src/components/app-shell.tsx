"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { authClient } from "@/lib/auth-client";
import { Mark } from "@/components/mark";

const links = [
  { href: "/app", label: "Bóveda", hint: "Nombres y pistas" },
  { href: "/app/requests", label: "Solicitudes", hint: "Aprobar un uso" },
  { href: "/app/agents", label: "Agentes", hint: "Quién pide" },
  { href: "/app/audit", label: "Auditoría", hint: "Sin valores" },
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
        <Mark href="/app" />
        <nav aria-label="Secciones">
          {links.map((link) => (
            <Link
              key={link.href}
              className="nav-link"
              href={link.href}
              aria-current={pathname === link.href ? "page" : undefined}
            >
              <strong>{link.label}</strong>
              <span>{link.hint}</span>
            </Link>
          ))}
        </nav>
        <div className="who">
          <div>
            <strong>{name}</strong>
            <div>{email}</div>
          </div>
          <button className="signout" type="button" onClick={() => void signOut()}>
            Salir
          </button>
        </div>
      </aside>
      <div className="main">{children}</div>
    </div>
  );
}
