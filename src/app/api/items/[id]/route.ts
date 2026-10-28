import { assertSameOrigin, handle, json } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { revokeItem } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const DELETE = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id } = await context.params;
    await revokeItem(actor, id, request);
    return json({ ok: true });
  });
