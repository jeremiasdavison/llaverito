import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { itemSchema } from "@/lib/validate";
import { createItem } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = (request: Request) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const body = await readJson(request, itemSchema);
    return json(
      await createItem(actor, { ...body, publicKey: body.publicKey || undefined }, request),
      201,
    );
  });
