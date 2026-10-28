import { AppShell } from "@/components/app-shell";
import { ConfigError } from "@/components/config-error";
import { ensurePersonalFolder } from "@/lib/bootstrap";
import { ConfigError as ConfigFailure } from "@/lib/errors";
import { getSessionUser } from "@/lib/session";
import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export default async function VaultLayout({ children }: { children: React.ReactNode }) {
  let user: Awaited<ReturnType<typeof getSessionUser>> = null;
  try {
    user = await getSessionUser();
  } catch (error) {
    if (error instanceof ConfigFailure) return <ConfigError />;
    throw error;
  }
  if (!user) redirect("/sign-in");
  try {
    await ensurePersonalFolder(user.id);
  } catch {
    return <ConfigError />;
  }
  return (
    <AppShell name={user.name} email={user.email}>
      {children}
    </AppShell>
  );
}
