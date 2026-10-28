import { createAgentToken, listAgentTokens } from "@/lib/agents";
import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { agentTokenSchema } from "@/lib/validate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = (request: Request) =>
  handle(request, async () => json(await listAgentTokens(await requireUser())));

export const POST = (request: Request) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const body = await readJson(request, agentTokenSchema);
    return json(await createAgentToken(actor, body.name, request), 201);
  });
