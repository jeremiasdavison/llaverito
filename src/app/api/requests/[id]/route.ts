import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireRelease } from "@/lib/release-auth";
import { decideRequest } from "@/lib/requests";
import { requireUser } from "@/lib/session";
import { decisionSchema } from "@/lib/validate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const POST = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const { id } = await context.params;
    const body = await readJson(request, decisionSchema);
    const actor = body.action === "approve" ? await requireRelease(request) : await requireUser();
    return json(await decideRequest(actor, id, body.action, request));
  });
