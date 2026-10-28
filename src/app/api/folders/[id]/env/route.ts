import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { envBindSchema } from "@/lib/validate";
import { bindEnv, envManifest } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const GET = (request: Request, context: Context) =>
  handle(request, async () => {
    const actor = await requireUser();
    const { id } = await context.params;
    return json(await envManifest(actor, id));
  });

export const POST = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id } = await context.params;
    const body = await readJson(request, envBindSchema);
    return json(await bindEnv(actor, id, body, request), 201);
  });
