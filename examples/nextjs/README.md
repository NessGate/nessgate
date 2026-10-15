# NessGate Inspect + Next.js

Return neutral evidence about an incoming caller from a Next.js App Router route
handler, using the published
[`@nessgate/inspect`](https://www.npmjs.com/package/@nessgate/inspect) package.
Evidence only — no allow/deny, no score.

`app/api/inspect/route.ts` is the whole integration:

```bash
npm i @nessgate/inspect
# then GET /api/inspect
```

## Runtime matters

`@nessgate/inspect` uses `node:dns` and `node:crypto`, so the route handler sets
`export const runtime = "nodejs"`. The **Edge runtime does not provide these**, so
on Edge the `network-verified` tier cannot run and verification degrades to the
header-based tiers (`claimed` / `directory-attributed`). Use the Node runtime for
the full evidence set.

Next.js `middleware.ts` runs only on the Edge runtime, so it can produce the
header-based tiers but not `network-verified`. For full evidence, use a Node
runtime route handler like the one here.

## Source IP

Use your platform's trusted client-IP field. On Vercel, the platform sets
`x-forwarded-for` (and strips client-supplied copies), so its leftmost value is
the real client. Do not trust a forwarding header from an untrusted hop —
network verification depends on the source IP being the real connection origin.
