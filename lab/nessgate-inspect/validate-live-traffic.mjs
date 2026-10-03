// RETIRED (2026-10-03) — do not revive in this form.
//
// This tool pulled (userAgent, clientIP) groups from zone analytics to measure
// Inspect against real traffic. The public privacy policy states that client IP
// addresses are not read or recorded for measurement; that stronger promise
// wins over the experiment, so the tool is disabled rather than the policy
// weakened. Any future validation must be opt-in traffic or non-identifying
// (e.g. User-Agent-only, with no per-IP dimension and no network attribution
// against real client addresses).
console.error("retired: this measurement read client IPs, which the privacy policy rules out; see the header comment");
process.exit(1);
