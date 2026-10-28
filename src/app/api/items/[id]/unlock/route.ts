import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { unlockSchema } from "@/lib/validate";
import { unlockItem } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const POST = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id } = await context.params;
    await readJson(request, unlockSchema);
    return json(await unlockItem(actor, id, request));
  });
