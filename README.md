# doc-detective

Document integrity certification platform. Certify a file (SHA-256 + Ed25519 signature + transparency log + optional RFC 3161 timestamp), then verify whether a later copy is authentic, format-only modified, or tampered.

## Stack

- Next.js (App Router) + TypeScript + Tailwind
- Prisma + MongoDB (Atlas or local; transactions require a replica set)
- Trust layer: signing keys, hash-chained log, Merkle checkpoints, TSA
- Format analyzers: PDF, images, DOCX/XLSX/PPTX, audio/video (ffmpeg)

## Setup

```bash
cp .env.example .env
# Set ED25519_PRIVATE_KEY (see .env.example for how to generate one)
npm install
npx prisma db push
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

### Database

`DATABASE_URL` must point at MongoDB. Prisma interactive transactions need a **replica set** (MongoDB Atlas provides this by default; for local `mongod`, start with `--replSet` and `rs.initiate()`).

Examples:

```bash
# Atlas
DATABASE_URL="mongodb+srv://USER:PASSWORD@cluster0.xxxxx.mongodb.net/doc-detective?retryWrites=true&w=majority"

# Local replica set
DATABASE_URL="mongodb://127.0.0.1:27017/doc-detective?replicaSet=rs0"
```

### Environment (see `.env.example`)

| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | MongoDB connection string (replica set required) |
| `ED25519_PRIVATE_KEY` | PKCS8 PEM for local signing (generate your own) |
| `ED25519_KEY_ID` | Active key id (default `local-dev`) |
| `SIGNING_PROVIDER` | `local` or `aws-kms` (stub) |
| `TSA_URL` | RFC 3161 TSA (default FreeTSA) |
| `CHECKPOINT_EVERY_N_ENTRIES` | When to timestamp the log |
| `CRON_SECRET` | Protects `/api/cron/checkpoint` (`Authorization: Bearer`) |
| `REDIS_URL` | Optional rate-limit backend |
| `WATERMARK_KEY` / `MAX_UPLOAD_MB` / `STORAGE_DIR` | As before |

## Scripts

```bash
npm run dev          # development server
npm test             # Vitest
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

## Known limitations

- Faint regional lightening on text documents after JPEG may not be detected.
- Relabelled log entries are only detected by the chain check — run the checkpoint cron every few minutes.
- v1 (legacy) certificates don't sign their analysis data until upgraded with `scripts/resign-v2.ts`.
