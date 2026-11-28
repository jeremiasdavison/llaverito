import type { Metadata } from "next";
import { Fraunces, Outfit } from "next/font/google";
import { connection } from "next/server";
import "./globals.css";

const sans = Outfit({ subsets: ["latin"], variable: "--font-sans" });
const display = Fraunces({ subsets: ["latin"], variable: "--font-display" });

export const metadata: Metadata = {
  title: "Llaverito",
  description: "Cofre de credenciales para agentes. El modelo no ve el secreto.",
  robots: { index: false, follow: false },
};

// La CSP del proxy lleva un nonce por request. Una página prerenderizada sale con <script> sin
// nonce y 'strict-dynamic' la bloquea, así que todo el árbol se renderiza por request.
export const dynamic = "force-dynamic";

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  await connection();
  return (
    <html lang="es">
      <body className={`${sans.variable} ${display.variable}`}>{children}</body>
    </html>
  );
}
