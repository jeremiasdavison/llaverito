import { z } from "zod";
import { HttpError } from "@/lib/errors";
import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { shareSchema } from "@/lib/validate";
import { createShare, listShares } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const querySchema = z.object({
  resourceType: z.enum(["folder", "item"]),
  resourceId: z.uuid(),
});

export const GET = (request: Request) =>
  handle(request, async () => {
    const actor = await requireUser();
    const url = new URL(request.url);
    const parsed = querySchema.safeParse({
      resourceType: url.searchParams.get("resourceType"),
      resourceId: url.searchParams.get("resourceId"),
    });
    if (!parsed.success) throw new HttpError(400, "Falta el recurso");
    return json(await listShares(actor, parsed.data.resourceType, parsed.data.resourceId));
  });

export const POST = (request: Request) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const body = await readJson(request, shareSchema);
    return json(await createShare(actor, body, request), 201);
  });
