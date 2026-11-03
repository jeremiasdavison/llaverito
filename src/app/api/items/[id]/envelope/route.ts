import { handle, json } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { getItemMaterial } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const GET = (request: Request, context: Context) =>
  handle(request, async () => {
    const actor = await requireUser();
    const { id } = await context.params;
    return json(await getItemMaterial(actor, id));
  });
