import { assertSameOrigin, handle, json } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { unbindEnv } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string; bindingId: string }> };

export const DELETE = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id, bindingId } = await context.params;
    await unbindEnv(actor, id, bindingId, request);
    return json({ ok: true });
  });
