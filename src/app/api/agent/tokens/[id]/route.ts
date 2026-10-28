import { revokeAgentToken } from "@/lib/agents";
import { assertSameOrigin, handle, json } from "@/lib/http";
import { requireUser } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const DELETE = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id } = await context.params;
    await revokeAgentToken(actor, id, request);
    return json({ ok: true });
  });
