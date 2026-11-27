import { toNextJsHandler } from "better-auth/next-js";
import { getAuth } from "@/lib/auth";
import { json, serviceErrorResponse } from "@/lib/http";
import { safeLog } from "@/lib/redact";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

async function handler(request: Request) {
  try {
    const auth = await getAuth();
    const handlers = toNextJsHandler(auth);
    const method = request.method as keyof typeof handlers;
    const fn = handlers[method];
    if (!fn) return new Response(null, { status: 405 });
    return await fn(request);
  } catch (error) {
    const mapped = serviceErrorResponse(error);
    if (mapped) return mapped;
    safeLog("auth request failed", {
      path: new URL(request.url).pathname,
      name: error instanceof Error ? error.name : "Error",
    });
    return json({ message: "Error interno", error: "Error interno" }, 500);
  }
}

export { handler as GET, handler as POST, handler as PATCH, handler as PUT, handler as DELETE };
