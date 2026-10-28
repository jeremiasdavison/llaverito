import { actorFromBearer } from "@/lib/agents";
import { handle, json, readJson } from "@/lib/http";
import { createItemRequest } from "@/lib/requests";
import { requestSchema } from "@/lib/validate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = (request: Request) =>
  handle(request, async () => {
    const { actor, tokenId } = await actorFromBearer(request.headers.get("authorization"));
    const body = await readJson(request, requestSchema);
    return json(await createItemRequest(actor, body, tokenId, request), 201);
  });
