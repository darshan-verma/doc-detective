import { prisma } from "@/lib/prisma";
import { LogVerifyButton } from "./LogVerifyButton";

export const dynamic = "force-dynamic";

export default async function LogPage() {
  const checkpoints = await prisma.checkpoint.findMany({
    orderBy: { toSeq: "desc" },
    take: 50,
  });

  const entryCount = await prisma.logEntry.count();

  return (
    <div className="space-y-6">
      <div>
        <p className="text-xs uppercase tracking-wider text-zinc-500">
          Transparency log
        </p>
        <h1 className="mt-1 text-2xl font-semibold text-zinc-900">
          Checkpoints
        </h1>
        <p className="mt-2 text-sm text-zinc-600">
          External RFC 3161 timestamps over Merkle roots of the append-only
          hash chain ({entryCount.toLocaleString()} log entries).
        </p>
      </div>

      <LogVerifyButton />

      {checkpoints.length === 0 ? (
        <div className="rounded-md bg-zinc-100 px-4 py-3 text-sm text-zinc-700">
          No checkpoints yet. They are created by the cron job once enough log
          entries accumulate.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-zinc-200 bg-white shadow-sm">
          <table className="min-w-full text-left text-sm">
            <thead className="border-b border-zinc-200 bg-zinc-50 text-xs uppercase tracking-wide text-zinc-500">
              <tr>
                <th className="px-4 py-3">Range</th>
                <th className="px-4 py-3">Merkle root</th>
                <th className="px-4 py-3">genTime</th>
                <th className="px-4 py-3">TSA</th>
              </tr>
            </thead>
            <tbody>
              {checkpoints.map((cp) => (
                <tr key={cp.id} className="border-b border-zinc-100">
                  <td className="px-4 py-3 font-mono text-xs">
                    {cp.fromSeq}–{cp.toSeq}
                  </td>
                  <td className="max-w-xs truncate px-4 py-3 font-mono text-xs">
                    {cp.merkleRoot}
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-700">
                    {cp.genTime
                      ? new Date(cp.genTime).toLocaleString()
                      : "—"}
                  </td>
                  <td className="max-w-[12rem] truncate px-4 py-3 text-xs text-zinc-600">
                    {cp.tsaUrl}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
