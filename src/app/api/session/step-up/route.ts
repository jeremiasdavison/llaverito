import { assertSameOrigin, handle, json, readJson } from "@/lib/http";
import { grantStepUp } from "@/lib/release-auth";
import { requireSession } from "@/lib/session";
import { stepUpSchema } from "@/lib/validate";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const POST = (request: Request) =>
  handle(request, async () => {
    assertSameOrigin(request);
    const { user, sessionId } = await requireSession();
    const body = await readJson(request, stepUpSchema);
    const granted = await grantStepUp(request, user, sessionId, body.password, body.code ?? "");
    const response = json({ ok: true, twoFactor: granted.twoFactor });
    response.headers.append("Set-Cookie", granted.cookie);
    return response;
  });
