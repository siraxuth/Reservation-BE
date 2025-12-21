// Audit Logging Service
// Records all authentication and security-related events

import { prisma } from '../config/database';

// Audit action types
export type AuditAction =
  | 'LOGIN_SUCCESS'
  | 'LOGIN_FAILED'
  | 'LOGIN_BLOCKED_LOCKOUT'
  | 'LOGOUT'
  | 'LOGOUT_ALL'
  | 'REGISTER'
  | 'PASSWORD_CHANGED'
  | 'PASSWORD_RESET_REQUESTED'
  | 'PASSWORD_RESET_COMPLETED'
  | 'EMAIL_VERIFIED'
  | 'EMAIL_VERIFICATION_SENT'
  | 'ACCOUNT_LOCKED'
  | 'ACCOUNT_UNLOCKED'
  | 'ACCOUNT_DISABLED'
  | 'ACCOUNT_ENABLED'
  | 'ADMIN_CREATED'
  | 'ROLE_CHANGED'
  | 'SESSION_CREATED'
  | 'SESSION_DELETED'
  | 'API_KEY_CREATED'
  | 'API_KEY_REVOKED'
  | 'OAUTH_LOGIN'
  | 'OAUTH_LINK';

export interface AuditLogData {
  userId?: string;
  apiKeyId?: string;
  action: AuditAction;
  entity: string;
  entityId?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  metadata?: any;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * Create an audit log entry
 * This function is non-blocking and will not throw errors to avoid disrupting the main flow
 */
export async function createAuditLog(data: AuditLogData): Promise<void> {
  try {
    await prisma.auditLog.create({
      data: {
        userId: data.userId,
        apiKeyId: data.apiKeyId,
        action: data.action,
        entity: data.entity,
        entityId: data.entityId,
        metadata: data.metadata,
        ipAddress: data.ipAddress,
        userAgent: data.userAgent,
      },
    });
  } catch (err) {
    // Don't throw - audit logging should not break the main flow
    console.error('[AuditLog] Failed to create log:', err);
  }
}

/**
 * Query audit logs with filters
 */
export async function getAuditLogs(options: {
  userId?: string;
  action?: AuditAction;
  entity?: string;
  startDate?: Date;
  endDate?: Date;
  page?: number;
  limit?: number;
}) {
  const { userId, action, entity, startDate, endDate, page = 1, limit = 50 } = options;

  const where: Record<string, unknown> = {};

  if (userId) where.userId = userId;
  if (action) where.action = action;
  if (entity) where.entity = entity;
  if (startDate || endDate) {
    where.createdAt = {};
    if (startDate) (where.createdAt as Record<string, unknown>).gte = startDate;
    if (endDate) (where.createdAt as Record<string, unknown>).lte = endDate;
  }

  const [logs, total] = await Promise.all([
    prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
      include: {
        user: { select: { email: true, name: true } },
      },
    }),
    prisma.auditLog.count({ where }),
  ]);

  return {
    logs,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  };
}

/**
 * Get recent security events for a user
 */
export async function getUserSecurityEvents(userId: string, limit: number = 10) {
  const securityActions: AuditAction[] = [
    'LOGIN_SUCCESS',
    'LOGIN_FAILED',
    'LOGIN_BLOCKED_LOCKOUT',
    'LOGOUT',
    'PASSWORD_CHANGED',
    'PASSWORD_RESET_COMPLETED',
    'ACCOUNT_LOCKED',
  ];

  return prisma.auditLog.findMany({
    where: {
      userId,
      action: { in: securityActions },
    },
    orderBy: { createdAt: 'desc' },
    take: limit,
    select: {
      id: true,
      action: true,
      ipAddress: true,
      userAgent: true,
      createdAt: true,
      metadata: true,
    },
  });
}

/**
 * Get failed login attempts count for monitoring
 */
export async function getFailedLoginAttempts(
  email: string,
  since: Date
): Promise<number> {
  return prisma.auditLog.count({
    where: {
      action: 'LOGIN_FAILED',
      entity: 'User',
      metadata: {
        path: ['email'],
        equals: email,
      },
      createdAt: { gte: since },
    },
  });
}

/**
 * Clean up old audit logs (retention policy)
 */
export async function cleanupOldAuditLogs(retentionDays: number = 90): Promise<number> {
  const cutoffDate = new Date();
  cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

  const result = await prisma.auditLog.deleteMany({
    where: {
      createdAt: { lt: cutoffDate },
    },
  });

  return result.count;
}
