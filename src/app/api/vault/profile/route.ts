import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { profileSchema } from "@/lib/validate";
import { readVaultProfile, saveVaultProfile } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = (request: Request) =>
  handle(request, async () => json({ profile: await readVaultProfile(await requireUser()) }));

export const POST = (request: Request) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const actor = await requireUser();
    const body = await readJson(request, profileSchema);
    return json(await saveVaultProfile(actor, body), 201);
  });
