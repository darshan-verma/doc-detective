import Link from "next/link";

export function Nav() {
  return (
    <header className="border-b border-zinc-200 bg-white">
      <div className="mx-auto flex max-w-3xl items-center justify-between px-4 py-4">
        <Link href="/" className="text-lg font-semibold tracking-tight text-zinc-900">
          doc-detective
        </Link>
        <nav className="flex gap-4 text-sm">
          <Link href="/certify" className="text-zinc-600 hover:text-zinc-900">
            Certify
          </Link>
          <Link href="/verify" className="text-zinc-600 hover:text-zinc-900">
            Verify
          </Link>
          <Link href="/log" className="text-zinc-600 hover:text-zinc-900">
            Log
          </Link>
        </nav>
      </div>
    </header>
  );
}
