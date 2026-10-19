/**
 * GH#234 — the webhook limiter must charge its budget only to requests the
 * handler actually served, and its default must sit above live delivery rates.
 *
 * The limiter is registered ahead of the webhook's own auth/validation
 * middleware, so counting on the way in let traffic rejected as unauthenticated
 * spend the budget. With a spoofable `x-forwarded-for` key, that bucket is the
 * one genuine Helius deliveries share — so the 429s landed on the real sender.
 */
import { describe, it, expect } from "vitest";
import { createWebhookRateLimiter, UNSERVED_STATUSES } from "../src/lib/webhookRateLimiter.js";

/** Minimal Hono-shaped context. `status` is what the downstream handler set. */
function ctx(ip: string, status: number) {
  const headers: Record<string, string> = {};
  return {
    req: { header: (k: string) => (k === "x-forwarded-for" ? ip : undefined) },
    res: { status },
    header: (k: string, v: string) => {
      headers[k] = v;
    },
    json: (body: unknown, code: number) => ({ body, code }) as unknown as Response,
    _headers: headers,
  };
}

const opts = { maxRequests: 3, windowMs: 60_000 };

describe("GH#234 webhook rate limiter", () => {
  it("does NOT charge the budget for requests rejected by auth", async () => {
    const rl = createWebhookRateLimiter(opts);
    for (let i = 0; i < 50; i++) {
      const c = ctx("1.2.3.4", 401);
      const out = await rl.middleware(c, async () => {});
      expect(out, `request ${i} must not be limited`).toBeUndefined();
    }
    expect(rl.buckets.get("1.2.3.4")?.count).toBe(0);
  });

  it("does not charge for any unserved status", async () => {
    const rl = createWebhookRateLimiter(opts);
    for (const status of UNSERVED_STATUSES) {
      await rl.middleware(ctx("5.6.7.8", status), async () => {});
    }
    expect(rl.buckets.get("5.6.7.8")?.count).toBe(0);
  });

  it("DOES charge for served requests, and still rejects once spent", async () => {
    const rl = createWebhookRateLimiter(opts);
    for (let i = 0; i < 3; i++) {
      const out = await rl.middleware(ctx("9.9.9.9", 200), async () => {});
      expect(out, `served request ${i} should pass`).toBeUndefined();
    }
    expect(rl.buckets.get("9.9.9.9")?.count).toBe(3);

    const blocked = (await rl.middleware(ctx("9.9.9.9", 200), async () => {})) as any;
    expect(blocked?.code).toBe(429);
  });

  it("an unauthenticated flood cannot deny a different, authenticated sender", async () => {
    // The whole point: the attacker names the real sender's IP (spoofable XFF)
    // and floods it with requests that auth will reject.
    const rl = createWebhookRateLimiter(opts);
    const victimIp = "203.0.113.7"; // stands in for a Helius egress address
    for (let i = 0; i < 100; i++) {
      await rl.middleware(ctx(victimIp, 401), async () => {});
    }
    // The genuine sender still has its full budget.
    for (let i = 0; i < 3; i++) {
      const out = await rl.middleware(ctx(victimIp, 200), async () => {});
      expect(out, `genuine delivery ${i} must still be served`).toBeUndefined();
    }
  });

  it("the window resets, and pruning drops expired buckets", async () => {
    let t = 1_000_000;
    const rl = createWebhookRateLimiter({ ...opts, now: () => t });
    for (let i = 0; i < 3; i++) await rl.middleware(ctx("4.4.4.4", 200), async () => {});
    expect(((await rl.middleware(ctx("4.4.4.4", 200), async () => {})) as any)?.code).toBe(429);

    t += 60_001;
    const out = await rl.middleware(ctx("4.4.4.4", 200), async () => {});
    expect(out, "a new window must serve again").toBeUndefined();

    t += 60_001;
    rl.pruneExpired();
    expect(rl.buckets.size).toBe(0);
  });

  it("missing x-forwarded-for falls into a single shared bucket, not a bypass", async () => {
    const rl = createWebhookRateLimiter(opts);
    const noIp = () => ({
      req: { header: () => undefined },
      res: { status: 200 },
      header: () => {},
      json: (body: unknown, code: number) => ({ body, code }) as unknown as Response,
    });
    for (let i = 0; i < 3; i++) await rl.middleware(noIp(), async () => {});
    expect(((await rl.middleware(noIp(), async () => {})) as any)?.code).toBe(429);
    expect(rl.buckets.has("unknown-ip")).toBe(true);
  });
});
