import type { Metadata } from "next";
import { AuthForm } from "@/components/auth-form";

export const dynamic = "force-dynamic";

export const metadata: Metadata = { title: "Crear cuenta · Llaverito" };

export default function SignUpPage() {
  return <AuthForm mode="sign-up" next="/app" />;
}
