import type { Metadata } from "next";
import { AuditClient } from "@/components/audit-client";

export const metadata: Metadata = { title: "Auditoría · Llaverito" };

export default function AuditPage() {
  return <AuditClient />;
}