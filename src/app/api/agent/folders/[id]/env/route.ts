import { actorFromBearer } from "@/lib/agents";
import { handle, json, readJson } from "@/lib/http";
import { createEnvRequest } from "@/lib/requests";
import { envRequestSchema } from "@/lib/validate";
import { envManifest } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const GET = (request: Request, context: Context) =>
  handle(request, async () => {
    const { actor } = await actorFromBearer(request.headers.get("authorization"));
    const { id } = await context.params;
    return json(await envManifest(actor, id));
  });

export const POST = (request: Request, context: Context) =>
  handle(request, async () => {
    const { actor, tokenId } = await actorFromBearer(request.headers.get("authorization"));
    const { id } = await context.params;
    const body = await readJson(request, envRequestSchema);
    return json(
      await createEnvRequest(actor, id, { ...body, repository: body.repository || undefined }, tokenId, request),
      201,
    );
  });
