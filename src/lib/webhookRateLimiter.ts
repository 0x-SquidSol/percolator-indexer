/**
 * Per-IP rate limiter for `/webhook/trades` (M-5), extracted from `index.ts`
 * so it can be tested against the real code rather than a copy — `index.ts`
 * calls `start()` at module scope, so importing it in a test boots the service.
 *
 * Two properties this encodes, both from GH#234:
 *
 * 1. The CHECK runs before the handler and the COUNT runs after it, and only
 *    for requests the handler actually served. This middleware is registered
 *    ahead of the webhook's own auth/validation middleware, so counting on the
 *    way in let traffic rejected as unauthenticated spend the budget. With a
 *    spoofable `x-forwarded-for` key that bucket is the one genuine Helius
 *    deliveries share, so the 429s would land on the real sender.
 *
 * 2. The budget has to sit ABOVE the real delivery rate. The webhook is
 *    registered on the program id for every transaction type
 *    (`HeliusWebhookManager.ts`, `transactionTypes: ["ANY"]`) and the handler
 *    expects 1-10 transactions per call (`routes/webhook.ts`), so the live v2
 *    wrapper's measured 438 tx/min (2026-10-19) is 44-438 POSTs/min.
 *
 * `x-forwarded-for` is still trusted as-is here, which is only sound if the
 * ingress proxy strips a client-supplied header and appends the real client IP.
 * That remains unverified — see GH#234. The load-bearing protection on this
 * route is the HMAC auth guard; this is a secondary DoS mitigation.
 */

/** Statuses meaning the request never reached the handler: validation or auth. */
export const UNSERVED_STATUSES: ReadonlySet<number> = new Set([400, 401, 403, 405, 413]);

export interface RateLimitBucket {
  count: number;
  resetTime: number;
}

export interface WebhookRateLimiterOptions {
  maxRequests: number;
  windowMs: number;
  /** Injectable for tests. */
  now?: () => number;
  onLimit?: (info: { ip: string; count: number }) => void;
}

export interface WebhookRateLimiter {
  /** Hono middleware. */
  middleware: (c: any, next: any) => Promise<Response | void>;
  /** Drop expired buckets; call on an interval to bound memory. */
  pruneExpired: () => void;
  /** Test/introspection handle. */
  buckets: Map<string, RateLimitBucket>;
}

export function createWebhookRateLimiter(opts: WebhookRateLimiterOptions): WebhookRateLimiter {
  const { maxRequests, windowMs } = opts;
  const now = opts.now ?? (() => Date.now());
  const buckets = new Map<string, RateLimitBucket>();

  const middleware = async (c: any, next: any): Promise<Response | void> => {
    const ip = c.req.header("x-forwarded-for")?.split(",")[0].trim() || "unknown-ip";
    const t = now();
    const existing = buckets.get(ip);
    const bucket =
      !existing || t > existing.resetTime ? { count: 0, resetTime: t + windowMs } : existing;
    buckets.set(ip, bucket);

    // The check stays ahead of the handler: a spent bucket rejects immediately,
    // so a flood cannot get through it.
    if (bucket.count >= maxRequests) {
      opts.onLimit?.({ ip, count: bucket.count });
      c.header("Retry-After", Math.ceil((bucket.resetTime - t) / 1000).toString());
      return c.json({ error: "Too many requests, please try again later" }, 429);
    }

    await next();

    // Only a served request spends budget. Trade-off, stated: requests already
    // in flight have not incremented, so a concurrent burst can overshoot by
    // roughly its own concurrency. That is acceptable for a secondary
    // mitigation, and strictly better than charging requests never served.
    if (!UNSERVED_STATUSES.has(c.res?.status)) {
      bucket.count++;
    }
  };

  const pruneExpired = () => {
    const t = now();
    for (const [ip, data] of buckets.entries()) {
      if (t > data.resetTime) buckets.delete(ip);
    }
  };

  return { middleware, pruneExpired, buckets };
}
