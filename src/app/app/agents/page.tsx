import type { Metadata } from "next";
import { AgentsClient } from "@/components/agents-client";

export const metadata: Metadata = { title: "Agentes · Llaverito" };

export default function AgentsPage() {
  return <AgentsClient />;
}
