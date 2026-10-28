import { toNextJsHandler } from "better-auth/next-js";
import { getAuth } from "@/lib/auth";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

async function handler(request: Request) {
  const auth = await getAuth();
  const handlers = toNextJsHandler(auth);
  const method = request.method as keyof typeof handlers;
  const fn = handlers[method];
  if (!fn) return new Response(null, { status: 405 });
  return fn(request);
}

export { handler as GET, handler as POST, handler as PATCH, handler as PUT, handler as DELETE };
