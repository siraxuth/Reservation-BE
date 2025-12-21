// Rate Limiting Middleware
import { Elysia } from 'elysia';
import { env } from '../config/env';
import { RateLimitError } from '../utils/errors';

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

// In-memory store (use Redis in production for distributed systems)
const store = new Map<string, RateLimitEntry>();

// Cleanup expired entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of store.entries()) {
    if (entry.resetAt < now) {
      store.delete(key);
    }
  }
}, 60000); // Cleanup every minute

/**
 * Get client identifier from request
 */
function getClientId(headers: Record<string, string | undefined>, ip?: string): string {
  // Try to get real IP from proxy headers
  const forwardedFor = headers['x-forwarded-for'];
  const realIp = headers['x-real-ip'];

  return forwardedFor?.split(',')[0]?.trim() || realIp || ip || 'unknown';
}

/**
 * Rate limit plugin
 */
export function rateLimit(options?: {
  windowMs?: number;
  maxRequests?: number;
  keyPrefix?: string;
}) {
  const windowMs = options?.windowMs || env.RATE_LIMIT_WINDOW_MS;
  const maxRequests = options?.maxRequests || env.RATE_LIMIT_MAX_REQUESTS;
  const keyPrefix = options?.keyPrefix || 'rl:';

  return new Elysia({ name: 'rateLimit' }).derive(({ headers, request }) => {
    const ip = (request as any).ip || 'unknown';
    const clientId = getClientId(headers, ip);
    const key = `${keyPrefix}${clientId}`;
    const now = Date.now();

    let entry = store.get(key);

    if (!entry || entry.resetAt < now) {
      entry = {
        count: 0,
        resetAt: now + windowMs,
      };
    }

    entry.count++;
    store.set(key, entry);

    // Check if rate limit exceeded
    if (entry.count > maxRequests) {
      const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
      throw new RateLimitError(
        `Too many requests. Please try again in ${retryAfter} seconds.`
      );
    }

    return {
      rateLimit: {
        remaining: maxRequests - entry.count,
        reset: entry.resetAt,
        limit: maxRequests,
      },
    };
  });
}

/**
 * Stricter rate limit for auth endpoints
 */
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 10, // 10 attempts
  keyPrefix: 'rl:auth:',
});

/**
 * Rate limit for file uploads
 */
export const uploadRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 10, // 10 uploads per minute
  keyPrefix: 'rl:upload:',
});
