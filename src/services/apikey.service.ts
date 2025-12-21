// API Key Service
import { prisma } from '../config/database';
import { generateApiKey } from '../utils/crypto';
import { NotFoundError, BadRequestError } from '../utils/errors';
import type { CreateApiKeyInput } from '../utils/validation';

export interface ApiKeyResponse {
  id: string;
  name: string;
  keyPrefix: string;
  permissions: string[];
  status: string;
  lastUsedAt: Date | null;
  expiresAt: Date | null;
  createdAt: Date;
}

/**
 * Create a new API key for a user
 */
export async function createApiKey(
  userId: string,
  input: CreateApiKeyInput
): Promise<{ apiKey: ApiKeyResponse; key: string }> {
  const { key, prefix } = generateApiKey();

  const apiKey = await prisma.aPIKey.create({
    data: {
      userId,
      name: input.name,
      key,
      keyPrefix: prefix,
      permissions: input.permissions,
      expiresAt: input.expiresAt ? new Date(input.expiresAt) : null,
    },
  });

  return {
    apiKey: {
      id: apiKey.id,
      name: apiKey.name,
      keyPrefix: apiKey.keyPrefix,
      permissions: apiKey.permissions,
      status: apiKey.status,
      lastUsedAt: apiKey.lastUsedAt,
      expiresAt: apiKey.expiresAt,
      createdAt: apiKey.createdAt,
    },
    key, // Only returned once when created
  };
}

/**
 * Get all API keys for a user
 */
export async function getUserApiKeys(userId: string): Promise<ApiKeyResponse[]> {
  const apiKeys = await prisma.aPIKey.findMany({
    where: { userId },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      permissions: true,
      status: true,
      lastUsedAt: true,
      expiresAt: true,
      createdAt: true,
    },
    orderBy: { createdAt: 'desc' },
  });

  return apiKeys;
}

/**
 * Get single API key
 */
export async function getApiKey(
  userId: string,
  keyId: string
): Promise<ApiKeyResponse> {
  const apiKey = await prisma.aPIKey.findFirst({
    where: { id: keyId, userId },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      permissions: true,
      status: true,
      lastUsedAt: true,
      expiresAt: true,
      createdAt: true,
    },
  });

  if (!apiKey) {
    throw new NotFoundError('API Key');
  }

  return apiKey;
}

/**
 * Update API key permissions
 */
export async function updateApiKeyPermissions(
  userId: string,
  keyId: string,
  permissions: string[]
): Promise<ApiKeyResponse> {
  const apiKey = await prisma.aPIKey.findFirst({
    where: { id: keyId, userId },
  });

  if (!apiKey) {
    throw new NotFoundError('API Key');
  }

  const updated = await prisma.aPIKey.update({
    where: { id: keyId },
    data: { permissions },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      permissions: true,
      status: true,
      lastUsedAt: true,
      expiresAt: true,
      createdAt: true,
    },
  });

  return updated;
}

/**
 * Revoke an API key
 */
export async function revokeApiKey(
  userId: string,
  keyId: string
): Promise<ApiKeyResponse> {
  const apiKey = await prisma.aPIKey.findFirst({
    where: { id: keyId, userId },
  });

  if (!apiKey) {
    throw new NotFoundError('API Key');
  }

  if (apiKey.status === 'REVOKED') {
    throw new BadRequestError('API Key is already revoked');
  }

  const updated = await prisma.aPIKey.update({
    where: { id: keyId },
    data: { status: 'REVOKED' },
    select: {
      id: true,
      name: true,
      keyPrefix: true,
      permissions: true,
      status: true,
      lastUsedAt: true,
      expiresAt: true,
      createdAt: true,
    },
  });

  return updated;
}

/**
 * Rotate an API key (revoke old and create new)
 */
export async function rotateApiKey(
  userId: string,
  keyId: string
): Promise<{ apiKey: ApiKeyResponse; key: string }> {
  const oldKey = await prisma.aPIKey.findFirst({
    where: { id: keyId, userId },
  });

  if (!oldKey) {
    throw new NotFoundError('API Key');
  }

  // Generate new key
  const { key, prefix } = generateApiKey();

  // Use transaction to revoke old and create new
  const [_, newApiKey] = await prisma.$transaction([
    prisma.aPIKey.update({
      where: { id: keyId },
      data: { status: 'REVOKED' },
    }),
    prisma.aPIKey.create({
      data: {
        userId,
        name: oldKey.name,
        key,
        keyPrefix: prefix,
        permissions: oldKey.permissions,
        expiresAt: oldKey.expiresAt,
      },
    }),
  ]);

  return {
    apiKey: {
      id: newApiKey.id,
      name: newApiKey.name,
      keyPrefix: newApiKey.keyPrefix,
      permissions: newApiKey.permissions,
      status: newApiKey.status,
      lastUsedAt: newApiKey.lastUsedAt,
      expiresAt: newApiKey.expiresAt,
      createdAt: newApiKey.createdAt,
    },
    key,
  };
}

/**
 * Delete an API key permanently
 */
export async function deleteApiKey(
  userId: string,
  keyId: string
): Promise<void> {
  const apiKey = await prisma.aPIKey.findFirst({
    where: { id: keyId, userId },
  });

  if (!apiKey) {
    throw new NotFoundError('API Key');
  }

  await prisma.aPIKey.delete({
    where: { id: keyId },
  });
}

/**
 * Validate API key and return user info
 */
export async function validateApiKey(key: string) {
  const apiKey = await prisma.aPIKey.findFirst({
    where: {
      key,
      status: 'ACTIVE',
      OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
    },
    include: { user: true },
  });

  if (!apiKey) {
    return null;
  }

  // Update last used
  await prisma.aPIKey.update({
    where: { id: apiKey.id },
    data: { lastUsedAt: new Date() },
  });

  return {
    apiKey: {
      id: apiKey.id,
      name: apiKey.name,
      permissions: apiKey.permissions,
    },
    user: {
      id: apiKey.user.id,
      email: apiKey.user.email,
      name: apiKey.user.name,
      role: apiKey.user.role,
    },
  };
}
