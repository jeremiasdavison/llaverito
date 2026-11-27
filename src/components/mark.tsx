import Link from "next/link";

export function Mark({ href = "/" }: { href?: string }) {
  return (
    <Link className="mark" href={href}>
      <i aria-hidden="true" />
      <span>Llaverito</span>
    </Link>
  );
}
