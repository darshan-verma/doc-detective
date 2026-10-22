# doc-detective

Document integrity certification platform. Certify a file (SHA-256 + Ed25519 signature + transparency log + optional RFC 3161 timestamp), then verify whether a later copy is authentic, format-only modified, or tampered.

## Stack

- Next.js (App Router) + TypeScript + Tailwind
- Prisma + SQLite (local); schema works with PostgreSQL
- Trust layer: signing keys, hash-chained log, Merkle checkpoints, TSA
- Format analyzers: PDF, images, DOCX/XLSX/PPTX, audio/video (ffmpeg)

## Setup

```bash
cp .env.example .env
npm install
npx prisma db push
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Environment (see `.env.example`)

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | SQLite `file:./dev.db` or Postgres URL |
| `ED25519_PRIVATE_KEY` | PKCS8 PEM for local signing |
| `ED25519_KEY_ID` | Active key id (default `local-dev`) |
| `SIGNING_PROVIDER` | `local` or `aws-kms` (stub) |
| `TSA_URL` | RFC 3161 TSA (default FreeTSA) |
| `CHECKPOINT_EVERY_N_ENTRIES` | When to timestamp the log |
| `CRON_SECRET` | Protects `/api/cron/checkpoint` |
| `REDIS_URL` | Optional rate-limit backend |
| `WATERMARK_KEY` / `MAX_UPLOAD_MB` / `STORAGE_DIR` | As before |

## Scripts

```bash
npm run dev          # development server
npm test             # Vitest (73+ tests)
npm run eval         # build corpus + confusion matrix
npm run build        # production build
npm run db:push      # sync Prisma schema
```

## Trust & APIs

- `POST /api/certify` — multipart `file`; optional `addVerificationStamp`, `parentCertId`, `ownerToken`
- `POST /api/verify` — multipart `file` + optional `certId`
- `POST /api/verify/report` — download verification report PDF
- `GET /.well-known/doc-detective/keys.json` — published public keys
- `GET /api/log/verify` — recompute hash chain
- `POST /api/cron/checkpoint` — Merkle + TSA checkpoint (`Authorization: Bearer $CRON_SECRET`)
- `GET /api/certificate/[certId]/proof` — offline proof bundle
- `POST /api/certificate/[certId]/revoke` — `{ ownerToken, reason }`
- Short link: `/v/<certId>` → verify with cert preloaded
- Transparency UI: `/log`

## Verdicts

`AUTHENTIC` · `MODIFIED_FORMAT_ONLY` · `TAMPERED` · `ANALYSIS_UNAVAILABLE` · `NOT_FOUND` · `REVOKED`

## Notes

- Stamping (QR) is opt-in; when on, the stamped bytes are what get certified.
- Owner token is returned once at certify time (hash only stored). Required for new versions / revoke.
- TSA proves the hash existed at a time — not that original contents are true.
- Private keys are never logged or stored in the database.
