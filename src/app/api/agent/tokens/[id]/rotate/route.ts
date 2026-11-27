import { rotateAgentToken } from "@/lib/agents";
import { assertSameOrigin, handle, json } from "@/lib/http";
import { requireRelease } from "@/lib/release-auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const POST = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireRelease(request);
    const { id } = await context.params;
    return json(await rotateAgentToken(actor, id, request));
  });
