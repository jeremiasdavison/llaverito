import { actorFromBearer } from "@/lib/agents";
import { handle, json } from "@/lib/http";
import { listVault } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = (request: Request) =>
  handle(request, async () => {
    const { actor } = await actorFromBearer(request.headers.get("authorization"));
    const vault = await listVault(actor);
    return json({
      folders: vault.folders,
      items: vault.items.map(({ id, folderId, name, kind, fingerprint, revokedAt, access }) => ({
        id,
        folderId,
        name,
        kind,
        fingerprint,
        revokedAt,
        access,
      })),
    });
  });
