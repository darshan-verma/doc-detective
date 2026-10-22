import Link from "next/link";

export default function HomePage() {
  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-3xl font-semibold tracking-tight text-zinc-900">
          doc-detective
        </h1>
        <p className="mt-2 max-w-xl text-zinc-600">
          Certify any file with a streaming SHA-256 fingerprint. Later, verify
          authenticity — or see exactly what changed if it was tampered with.
        </p>
      </div>

      <div className="flex flex-wrap gap-3">
        <Link
          href="/certify"
          className="rounded-md bg-zinc-900 px-5 py-2.5 text-sm font-medium text-white hover:bg-zinc-800"
        >
          Certify a file
        </Link>
        <Link
          href="/verify"
          className="rounded-md border border-zinc-300 bg-white px-5 py-2.5 text-sm font-medium text-zinc-800 hover:bg-zinc-50"
        >
          Verify a file
        </Link>
      </div>

      <ul className="list-inside list-disc space-y-1 text-sm text-zinc-600">
        <li>Original bytes are stored untouched — the hash never lies</li>
        <li>
          Certified downloads rename the file only (e.g.{" "}
          <code className="rounded bg-zinc-100 px-1 text-xs">
            report_doc-detective_K7X2M9.pdf
          </code>
          )
        </li>
        <li>Text, PDF, DOCX, and binary diffs when something changes</li>
      </ul>
    </div>
  );
}
