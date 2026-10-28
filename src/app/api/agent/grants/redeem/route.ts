import { actorFromBearer } from "@/lib/agents";
import { handle, json, readJson } from "@/lib/http";
import { redeemGrant } from "@/lib/requests";
import { redeemSchema } from "@/lib/validate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = (request: Request) =>
  handle(request, async () => {
    const { actor } = await actorFromBearer(request.headers.get("authorization"));
    const body = await readJson(request, redeemSchema);
    return json(await redeemGrant(actor, body.grantId, request));
  });
