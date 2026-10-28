import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { folderPatchSchema } from "@/lib/validate";
import { deleteFolder, updateFolder } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const PATCH = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id } = await context.params;
    const body = await readJson(request, folderPatchSchema);
    return json(await updateFolder(actor, id, body, request));
  });

export const DELETE = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id } = await context.params;
    await deleteFolder(actor, id, request);
    return json({ ok: true });
  });
