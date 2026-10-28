import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { createEnvRequest } from "@/lib/requests";
import { requireUser } from "@/lib/session";
import { envRequestSchema } from "@/lib/validate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const POST = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id } = await context.params;
    const body = await readJson(request, envRequestSchema);
    return json(
      await createEnvRequest(actor, id, { ...body, repository: body.repository || undefined }, null, request),
      201,
    );
  });
