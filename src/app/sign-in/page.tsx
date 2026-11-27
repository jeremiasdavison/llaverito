import { AuthForm } from "@/components/auth-form";
import { safeAppPath } from "@/lib/paths";

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const params = await searchParams;
  const next = safeAppPath(params.next);
  return <AuthForm mode="sign-in" next={next} />;
}
