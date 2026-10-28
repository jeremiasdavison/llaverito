import { AuthForm } from "@/components/auth-form";

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const params = await searchParams;
  const next = params.next?.startsWith("/app") ? params.next : "/app";
  return <AuthForm mode="sign-in" next={next} />;
}
