import { handle, json } from "@/lib/http";
import { listGithubRepos, githubAccount } from "@/lib/github";
import { requireUser } from "@/lib/session";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = (request: Request) =>
  handle(request, async () => {
    const actor = await requireUser();
    const connected = Boolean(await githubAccount(actor));
    if (!connected) return json({ connected: false, repos: [] });
    return json({ connected: true, repos: await listGithubRepos(actor) });
  });
