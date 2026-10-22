import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Node filesystem / crypto APIs in API routes — keep serverful defaults
  serverExternalPackages: [
    "pdf-parse",
    "pdfjs-dist",
    "mammoth",
    "@prisma/client",
    "@napi-rs/canvas",
    "sharp",
  ],
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
