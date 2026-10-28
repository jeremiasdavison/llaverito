import { handle, json } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { listVault } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = (request: Request) =>
  handle(request, async () => {
    const actor = await requireUser();
    return json(await listVault(actor));
  });
