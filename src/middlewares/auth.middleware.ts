// Authentication Middleware
import { Elysia } from 'elysia';
import { bearer } from '@elysiajs/bearer';
import { validateSession, type AuthUser } from '../services/auth.service';
import { prisma } from '../config/database';
import { UnauthorizedError, ForbiddenError } from '../utils/errors';
import type { Role } from '@prisma/client';

// Re-export AuthUser for convenience
export type { AuthUser } from '../services/auth.service';

// Type for API Key
export interface ApiKeyInfo {
  id: string;
  name: string;
  permissions: string[];
}

/**
 * Helper function to extract auth from request
 */
async function extractAuth(bearerToken: string | undefined, headers: Record<string, string | undefined>) {
  let user: AuthUser | undefined;
  let apiKey: ApiKeyInfo | undefined;

  console.log('extractAuth called:', {
    hasBearer: !!bearerToken,
    bearerPrefix: bearerToken ? bearerToken.substring(0, 10) + '...' : null,
    hasApiKey: !!headers['x-api-key'],
  });

  // Check for bearer token
  if (bearerToken) {
    const authUser = await validateSession(bearerToken);
    console.log('Bearer validation result:', { hasUser: !!authUser });
    if (authUser) {
      user = authUser;
    }
  }

  // Check for API key in header
  const apiKeyHeader = headers['x-api-key'];
  if (apiKeyHeader && !user) {
    const key = await prisma.aPIKey.findFirst({
      where: {
        key: apiKeyHeader,
        status: 'ACTIVE',
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      },
      include: { user: true },
    });

    if (key) {
      apiKey = {
        id: key.id,
        name: key.name,
        permissions: key.permissions,
      };

      // Update last used
      await prisma.aPIKey.update({
        where: { id: key.id },
        data: { lastUsedAt: new Date() },
      });

      user = {
        id: key.user.id,
        email: key.user.email,
        name: key.user.name,
        phone: key.user.phone,
        avatar: key.user.avatar,
        role: key.user.role,
        createdAt: key.user.createdAt,
      };
    }
  }

  return { user, apiKey };
}

// Type for authenticated context
export type AuthenticatedContext = {
  user: AuthUser;
  apiKey: ApiKeyInfo | undefined;
};

export type OptionalAuthContext = {
  user: AuthUser | undefined;
  apiKey: ApiKeyInfo | undefined;
};

/**
 * Auth plugin - validates bearer token or API key
 * Returns user and apiKey in context
 */
export const authPlugin = new Elysia({ name: 'auth' })
  .use(bearer())
  .derive(async ({ bearer, headers }) => {
    console.log('=== authPlugin.derive START ===', { hasBearer: !!bearer });
    const result = await extractAuth(bearer, headers);
    console.log('=== authPlugin.derive END ===', { hasUser: !!result.user });
    return result;
  });

/**
 * Require authentication - throws if not authenticated
 */
export const requireAuth = new Elysia({ name: 'requireAuth' })
  .use(bearer())
  .derive(async ({ bearer: bearerToken, headers, request }) => {
    console.log('=== requireAuth.derive START ===', {
      hasBearer: !!bearerToken,
      bearerPrefix: bearerToken ? bearerToken.substring(0, 10) + '...' : null,
    });

    // Try to get bearer from Authorization header directly if not provided
    let token = bearerToken;
    if (!token) {
      const authHeader = request.headers.get('authorization');
      if (authHeader?.startsWith('Bearer ')) {
        token = authHeader.slice(7);
        console.log('Got token from header directly:', token.substring(0, 10) + '...');
      }
    }

    const auth = await extractAuth(token, headers);
    console.log('=== requireAuth.derive END ===', { hasUser: !!auth.user });

    if (!auth.user) {
      throw new UnauthorizedError('Authentication required');
    }
    return auth as AuthenticatedContext;
  });

/**
 * Require specific role(s)
 */
export function requireRole(...roles: Role[]) {
  return new Elysia({ name: `requireRole:${roles.join(',')}` })
    .use(bearer())
    .derive(async ({ bearer, headers }) => {
      const auth = await extractAuth(bearer, headers);
      if (!auth.user) {
        throw new UnauthorizedError('Authentication required');
      }
      if (!roles.includes(auth.user.role)) {
        throw new ForbiddenError(`Required role: ${roles.join(' or ')}`);
      }
      return auth as AuthenticatedContext;
    });
}

/**
 * Require admin role
 */
export const requireAdmin = requireRole('ADMIN');

/**
 * Require vendor role
 */
export const requireVendor = requireRole('VENDOR');

/**
 * Require vendor or admin role
 */
export const requireVendorOrAdmin = requireRole('VENDOR', 'ADMIN');

/**
 * Optional auth - doesn't throw if not authenticated
 */
export const optionalAuth = authPlugin;

/**
 * Check API key permission
 */
export function requireApiPermission(permission: string) {
  return new Elysia({ name: `requireApiPermission:${permission}` })
    .use(bearer())
    .derive(async ({ bearer, headers }) => {
      const auth = await extractAuth(bearer, headers);
      if (!auth.user) {
        throw new UnauthorizedError('Authentication required');
      }
      // If using API key, check permission
      if (auth.apiKey && !auth.apiKey.permissions.includes(permission)) {
        throw new ForbiddenError(`Missing permission: ${permission}`);
      }
      return auth as AuthenticatedContext;
    });
}
