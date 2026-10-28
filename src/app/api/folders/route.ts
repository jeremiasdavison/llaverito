import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { folderSchema } from "@/lib/validate";
import { createFolder } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = (request: Request) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const body = await readJson(request, folderSchema);
    return json(await createFolder(actor, body, request), 201);
  });
