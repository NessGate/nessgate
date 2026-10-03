// Public attribution directory (lab-only) — well-known automated-agent /
// crawler User-Agent patterns and the operator each PUBLICLY advertises.
//
// This is a directory of PUBLISHED, self-declared identifiers, not proof. A
// User-Agent is a plaintext request header: trivially spoofable, and a match here
// binds to nothing. Inspect therefore reports a match as "directory-attributed"
// (a public directory recognizes the declared string) with an explicit note that
// it rests on an unverified header — real binding needs a verified signature or
// verified reverse-DNS. Nothing here is a trust or reputation judgment.
//
// Entries are public facts (each operator documents the UA at the linked page).

export const AGENT_DIRECTORY = [
  { re: /GPTBot/i, operator: "OpenAI", info: "https://platform.openai.com/docs/bots" },
  { re: /ChatGPT-User/i, operator: "OpenAI (ChatGPT user-triggered fetch)", info: "https://platform.openai.com/docs/bots" },
  { re: /OAI-SearchBot/i, operator: "OpenAI (search)", info: "https://platform.openai.com/docs/bots" },
  { re: /ClaudeBot/i, operator: "Anthropic", info: "https://support.anthropic.com/en/articles/8896518" },
  { re: /Claude-User|Claude-Web|anthropic-ai/i, operator: "Anthropic", info: "https://support.anthropic.com/en/articles/8896518" },
  { re: /PerplexityBot/i, operator: "Perplexity", info: "https://docs.perplexity.ai/guides/bots" },
  { re: /Perplexity-User/i, operator: "Perplexity (user-triggered)", info: "https://docs.perplexity.ai/guides/bots" },
  { re: /Google-Extended/i, operator: "Google (AI training control token)", info: "https://developers.google.com/search/docs/crawling-indexing/overview-google-crawlers" },
  { re: /Googlebot/i, operator: "Google", info: "https://developers.google.com/search/docs/crawling-indexing/googlebot" },
  { re: /bingbot|BingPreview/i, operator: "Microsoft (Bing)", info: "https://www.bing.com/webmasters/help/which-crawlers-does-bing-use-8c184ec0" },
  { re: /Applebot(-Extended)?/i, operator: "Apple", info: "https://support.apple.com/en-us/119829" },
  { re: /Amazonbot/i, operator: "Amazon", info: "https://developer.amazon.com/amazonbot" },
  { re: /Bytespider/i, operator: "ByteDance", info: "https://www.bytedance.com" },
  { re: /meta-externalagent|FacebookBot/i, operator: "Meta", info: "https://developers.facebook.com/docs/sharing/webmasters/web-crawlers" },
  { re: /CCBot/i, operator: "Common Crawl", info: "https://commoncrawl.org/ccbot" },
  { re: /cohere-ai|cohere-training-data-crawler/i, operator: "Cohere", info: "https://cohere.com" },
  { re: /DuckAssistBot/i, operator: "DuckDuckGo", info: "https://duckduckgo.com/duckduckgo-help-pages/results/duckassistbot" },
  { re: /YouBot/i, operator: "You.com", info: "https://about.you.com/youbot" },
];

// Pure: match a User-Agent string against the directory. Returns the first match
// with its provenance, or null. A match is attribution of a DECLARED string only.
export function matchUserAgent(ua) {
  if (typeof ua !== "string" || !ua) return null;
  for (const e of AGENT_DIRECTORY) {
    if (e.re.test(ua)) return { operator: e.operator, info: e.info, pattern: e.re.source };
  }
  return null;
}
