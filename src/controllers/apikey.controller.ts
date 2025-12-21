// API Key Controller
import { Elysia, t } from 'elysia';
import * as apiKeyService from '../services/apikey.service';
import { requireAuth, type AuthUser } from '../middlewares/auth.middleware';
import { success } from '../utils/response';
import { createApiKeySchema } from '../utils/validation';
import { BadRequestError } from '../utils/errors';

// Type helper for authenticated context
type AuthCtx = { user: AuthUser };

export const apiKeyController = new Elysia({ prefix: '/api-keys' })
  .use(requireAuth)

  // List user's API keys
  .get(
    '/',
    async (ctx) => {
      const { user } = ctx as unknown as AuthCtx;
      const apiKeys = await apiKeyService.getUserApiKeys(user.id);
      return success(apiKeys);
    },
    {
      detail: {
        tags: ['API Keys'],
        summary: 'List API keys',
        description: 'Get all API keys for current user',
      },
    }
  )

  // Create new API key
  .post(
    '/',
    async (ctx) => {
      const { user, body } = ctx as unknown as AuthCtx & { body: any };
      const validated = createApiKeySchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const result = await apiKeyService.createApiKey(user.id, validated.data);
      return success(
        result,
        'API key created. Save the key now - it will not be shown again.'
      );
    },
    {
      body: t.Object({
        name: t.String(),
        permissions: t.Optional(t.Array(t.String())),
        expiresAt: t.Optional(t.String()),
      }),
      detail: {
        tags: ['API Keys'],
        summary: 'Create API key',
        description: 'Create a new API key',
      },
    }
  )

  // Get single API key
  .get(
    '/:keyId',
    async (ctx) => {
      const { user, params } = ctx as unknown as AuthCtx & { params: { keyId: string } };
      const apiKey = await apiKeyService.getApiKey(user.id, params.keyId);
      return success(apiKey);
    },
    {
      params: t.Object({
        keyId: t.String(),
      }),
      detail: {
        tags: ['API Keys'],
        summary: 'Get API key',
        description: 'Get details of a specific API key',
      },
    }
  )

  // Update API key permissions
  .patch(
    '/:keyId/permissions',
    async (ctx) => {
      const { user, params, body } = ctx as unknown as AuthCtx & { params: { keyId: string }; body: { permissions: string[] } };
      const apiKey = await apiKeyService.updateApiKeyPermissions(
        user.id,
        params.keyId,
        body.permissions
      );
      return success(apiKey, 'Permissions updated');
    },
    {
      params: t.Object({
        keyId: t.String(),
      }),
      body: t.Object({
        permissions: t.Array(t.String()),
      }),
      detail: {
        tags: ['API Keys'],
        summary: 'Update permissions',
        description: 'Update API key permissions',
      },
    }
  )

  // Revoke API key
  .post(
    '/:keyId/revoke',
    async (ctx) => {
      const { user, params } = ctx as unknown as AuthCtx & { params: { keyId: string } };
      const apiKey = await apiKeyService.revokeApiKey(user.id, params.keyId);
      return success(apiKey, 'API key revoked');
    },
    {
      params: t.Object({
        keyId: t.String(),
      }),
      detail: {
        tags: ['API Keys'],
        summary: 'Revoke API key',
        description: 'Revoke an API key (cannot be undone)',
      },
    }
  )

  // Rotate API key
  .post(
    '/:keyId/rotate',
    async (ctx) => {
      const { user, params } = ctx as unknown as AuthCtx & { params: { keyId: string } };
      const result = await apiKeyService.rotateApiKey(user.id, params.keyId);
      return success(
        result,
        'API key rotated. Save the new key now - it will not be shown again.'
      );
    },
    {
      params: t.Object({
        keyId: t.String(),
      }),
      detail: {
        tags: ['API Keys'],
        summary: 'Rotate API key',
        description: 'Revoke old key and generate a new one with same permissions',
      },
    }
  )

  // Delete API key
  .delete(
    '/:keyId',
    async (ctx) => {
      const { user, params } = ctx as unknown as AuthCtx & { params: { keyId: string } };
      await apiKeyService.deleteApiKey(user.id, params.keyId);
      return success(null, 'API key deleted');
    },
    {
      params: t.Object({
        keyId: t.String(),
      }),
      detail: {
        tags: ['API Keys'],
        summary: 'Delete API key',
        description: 'Permanently delete an API key',
      },
    }
  );
