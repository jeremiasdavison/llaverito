import type { Metadata } from "next";
import { RequestsClient } from "@/components/requests-client";

export const metadata: Metadata = { title: "Solicitudes · Llaverito" };

export default function RequestsPage() {
  return <RequestsClient />;
}
