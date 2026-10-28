import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { createItemRequest, listRequests } from "@/lib/requests";
import { requireUser } from "@/lib/session";
import { requestSchema } from "@/lib/validate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = (request: Request) =>
  handle(request, async () => json(await listRequests(await requireUser())));

export const POST = (request: Request) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const body = await readJson(request, requestSchema);
    return json(await createItemRequest(actor, body, null, request), 201);
  });
