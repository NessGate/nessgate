// Runnable drop-in example (lab-only). Uses the SAME middleware you'd pass to
// app.use() in Express, here on a plain node:http server so it runs with zero
// dependencies. For every request it logs the six fields and returns the full
// normalized Inspect result. No allow/deny, no policy — pure observation.
//
//   node integrations/example.mjs
//   curl -s localhost:8798/some/path -H 'user-agent: Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)' | jq .summary
//
// (From localhost the source IP is loopback, so a bot UA will be directory-attributed
//  but NOT network-verified — correctly, because the request did not originate from
//  the operator's infrastructure. That is the honest result.)

import { createServer } from "node:http";
import { nessgateInspect, summarize } from "../../../packages/inspect/middleware.mjs";

// This is the entire integration:
const inspectMiddleware = nessgateInspect({ log: true });

createServer((req, res) => {
  inspectMiddleware(req, res, () => {
    // req.nessgate is now populated. A site owner does whatever they want here;
    // this demo just surfaces the six fields + the full result.
    const result = req.nessgate;
    res.writeHead(200, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify({ summary: summarize(result), full: result }, null, 2));
  });
}).listen(process.env.PORT || 8798, () => {
  console.log(`example on http://localhost:${process.env.PORT || 8798}  (the whole integration is 2 lines: import + app.use)`);
});
