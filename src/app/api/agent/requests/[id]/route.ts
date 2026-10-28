import { actorFromBearer } from "@/lib/agents";
import { handle, json } from "@/lib/http";
import { agentRequestStatus } from "@/lib/requests";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const GET = (request: Request, context: Context) =>
  handle(request, async () => {
    const { actor } = await actorFromBearer(request.headers.get("authorization"));
    const { id } = await context.params;
    return json(await agentRequestStatus(actor, id));
  });
