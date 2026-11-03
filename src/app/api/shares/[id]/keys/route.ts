import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { shareKeysSchema } from "@/lib/validate";
import { approveShareKeys } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const POST = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id } = await context.params;
    const body = await readJson(request, shareKeysSchema);
    return json(await approveShareKeys(actor, id, body.wraps, request));
  });
