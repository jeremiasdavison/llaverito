import { z } from "zod";
import { HttpError } from "@/lib/errors";
import { handle, json } from "@/lib/http";
import { requireUser } from "@/lib/session";
import { publicKeyForEmail } from "@/lib/vault";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export const GET = (request: Request) =>
  handle(request, async () => {
    await requireUser();
    const email = new URL(request.url).searchParams.get("email") ?? "";
    if (!z.string().email().safeParse(email).success) throw new HttpError(400, "Email inválido");
    return json(await publicKeyForEmail(email));
  });
