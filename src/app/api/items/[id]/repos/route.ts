import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { githubLinkSchema } from "@/lib/validate";
import { linkGithubRepo } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Context = { params: Promise<{ id: string }> };

export const POST = (request: Request, context: Context) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const { id } = await context.params;
    const body = await readJson(request, githubLinkSchema);
    return json(await linkGithubRepo(actor, id, body.githubRepo, request), 201);
  });
