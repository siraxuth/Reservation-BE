// Error Handling Middleware
import { Elysia } from 'elysia';
import {
  AppError,
  ValidationError,
  formatErrorResponse,
  getErrorStatusCode,
} from '../utils/errors';
import { env } from '../config/env';

/**
 * Global error handler
 */
export const errorHandler = new Elysia({ name: 'errorHandler' }).onError(
  ({ error, set }) => {
    // Log error in development
    if (!env.IS_PRODUCTION) {
      console.error('Error:', error);
    }

    // Get status code
    const statusCode = getErrorStatusCode(error);
    set.status = statusCode;

    // Format response
    const response = formatErrorResponse(error);

    // Add validation details if applicable
    if (error instanceof ValidationError) {
      return {
        ...response,
        details: error.errors,
      };
    }

    // Add stack trace in development
    if (!env.IS_PRODUCTION && error instanceof Error) {
      return {
        ...response,
        stack: error.stack,
      };
    }

    return response;
  }
);

/**
 * Request logging middleware
 */
export const requestLogger = new Elysia({ name: 'requestLogger' })
  .onRequest(({ request, store }) => {
    (store as any).startTime = Date.now();

    if (!env.IS_PRODUCTION) {
      console.log(`→ ${request.method} ${new URL(request.url).pathname}`);
    }
  })
  .onAfterResponse(({ request, set, store }) => {
    const duration = Date.now() - ((store as any).startTime || Date.now());

    if (!env.IS_PRODUCTION) {
      console.log(
        `← ${request.method} ${new URL(request.url).pathname} ${set.status} ${duration}ms`
      );
    }
  });

/**
 * Security headers middleware
 */
export const securityHeaders = new Elysia({ name: 'securityHeaders' }).onAfterResponse(
  ({ set }) => {
    // Set security headers
    set.headers['X-Content-Type-Options'] = 'nosniff';
    set.headers['X-Frame-Options'] = 'DENY';
    set.headers['X-XSS-Protection'] = '1; mode=block';
    set.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin';

    if (env.IS_PRODUCTION) {
      set.headers['Strict-Transport-Security'] =
        'max-age=31536000; includeSubDomains';
    }
  }
);
