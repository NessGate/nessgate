// Inspect an incoming caller in a Next.js App Router route handler.
//
//   npm i @nessgate/inspect
//   GET /api/inspect
//
// The Node.js runtime is required: @nessgate/inspect uses node:dns and node:crypto,
// which the Edge runtime does not provide. On Edge, network-verified cannot run.

import { inspect } from "@nessgate/inspect";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const headers = Object.fromEntries(request.headers);

  // Source IP: use your platform's trusted client-IP field. On Vercel the
  // platform sets x-forwarded-for and strips client-supplied copies, so the
  // leftmost value is the real client. Only trust a forwarding header from a
  // platform you control; network verification depends on this IP being the
  // real connection source.
  const sourceIp = (headers["x-forwarded-for"] || "").split(",")[0].trim() || undefined;

  const evidence = await inspect(
    { method: request.method, url: request.url, headers },
    { sourceIp }
  );

  return Response.json(evidence);
}
