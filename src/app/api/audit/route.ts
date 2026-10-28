import { listAudit } from "@/lib/audit";
import { handle, json } from "@/lib/http";
import { requireUser } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = (request: Request) =>
  handle(request, async () => json(await listAudit(await requireUser())));
