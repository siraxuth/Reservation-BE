// Authentication Service
import { prisma } from '../config/database';
import { env } from '../config/env';
import { hashPassword, comparePassword, generateSessionToken } from '../utils/crypto';
import { UnauthorizedError, ConflictError, BadRequestError } from '../utils/errors';
import { createAuditLog } from './audit.service';
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendAccountLockedEmail,
} from './email.service';
import type { RegisterInput, LoginInput } from '../utils/validation';
import type { Role } from '@prisma/client';
import { nanoid } from 'nanoid';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  phone: string | null;
  avatar: string | null;
  role: Role;
  createdAt: Date;
}

export interface SessionData {
  user: AuthUser;
  token: string;
  expiresAt: Date;
}

// Calculate session expiry
function getSessionExpiry(): Date {
  const expiresIn = env.JWT_EXPIRES_IN;
  const match = expiresIn.match(/^(\d+)([dhms])$/);
  if (!match) {
    return new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  let ms: number;
  switch (unit) {
    case 'd':
      ms = value * 24 * 60 * 60 * 1000;
      break;
    case 'h':
      ms = value * 60 * 60 * 1000;
      break;
    case 'm':
      ms = value * 60 * 1000;
      break;
    case 's':
      ms = value * 1000;
      break;
    default:
      ms = 7 * 24 * 60 * 60 * 1000;
  }

  return new Date(Date.now() + ms);
}

// ============================================
// Account Lockout Functions
// ============================================

/**
 * Check if account is locked
 */
async function checkAccountLockout(user: {
  id: string;
  email: string;
  lockedUntil: Date | null;
}): Promise<void> {
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    const remainingMinutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 60000);

    await createAuditLog({
      userId: user.id,
      action: 'LOGIN_BLOCKED_LOCKOUT',
      entity: 'User',
      entityId: user.id,
      metadata: { remainingMinutes, email: user.email },
    });

    throw new UnauthorizedError(
      `Account is locked due to too many failed login attempts. Please try again in ${remainingMinutes} minute(s).`
    );
  }
}

/**
 * Record a failed login attempt
 */
async function recordFailedLogin(userId: string, email: string): Promise<void> {
  const user = await prisma.user.update({
    where: { id: userId },
    data: {
      failedLoginAttempts: { increment: 1 },
      lastFailedLogin: new Date(),
    },
    select: { failedLoginAttempts: true, name: true },
  });

  await createAuditLog({
    userId,
    action: 'LOGIN_FAILED',
    entity: 'User',
    entityId: userId,
    metadata: { email, failedAttempts: user.failedLoginAttempts },
  });

  // Check if should lock account
  if (user.failedLoginAttempts >= env.ACCOUNT_LOCKOUT_THRESHOLD) {
    const lockUntil = new Date(Date.now() + env.ACCOUNT_LOCKOUT_DURATION_MINUTES * 60 * 1000);

    await prisma.user.update({
      where: { id: userId },
      data: { lockedUntil: lockUntil },
    });

    await createAuditLog({
      userId,
      action: 'ACCOUNT_LOCKED',
      entity: 'User',
      entityId: userId,
      metadata: {
        failedAttempts: user.failedLoginAttempts,
        lockedUntil: lockUntil.toISOString(),
      },
    });

    // Send notification email
    await sendAccountLockedEmail(email, user.name, lockUntil);
  }
}

/**
 * Reset failed login attempts on successful login
 */
async function resetFailedLoginAttempts(userId: string): Promise<void> {
  await prisma.user.update({
    where: { id: userId },
    data: {
      failedLoginAttempts: 0,
      lockedUntil: null,
      lastFailedLogin: null,
    },
  });
}

// ============================================
// Core Authentication Functions
// ============================================

/**
 * Register a new user
 */
export async function register(input: RegisterInput): Promise<SessionData> {
  const existingUser = await prisma.user.findUnique({
    where: { email: input.email },
  });

  if (existingUser) {
    throw new ConflictError('User with this email already exists');
  }

  const hashedPassword = await hashPassword(input.password);

  const user = await prisma.user.create({
    data: {
      email: input.email,
      name: input.name,
      phone: input.phone,
      password: hashedPassword,
      role: input.role as Role,
      emailVerified: false,
    },
    select: {
      id: true,
      email: true,
      name: true,
      phone: true,
      avatar: true,
      role: true,
      createdAt: true,
    },
  });

  // Generate and send email verification
  const verificationToken = await generateEmailVerificationToken(user.id);
  await sendVerificationEmail(user.email, user.name, verificationToken);

  await createAuditLog({
    userId: user.id,
    action: 'REGISTER',
    entity: 'User',
    entityId: user.id,
    metadata: { email: user.email, role: user.role },
  });

  return createSession(user);
}

/**
 * Login with email and password
 */
export async function login(input: LoginInput): Promise<SessionData> {
  const user = await prisma.user.findUnique({
    where: { email: input.email },
    select: {
      id: true,
      email: true,
      name: true,
      phone: true,
      avatar: true,
      role: true,
      password: true,
      isActive: true,
      lockedUntil: true,
      failedLoginAttempts: true,
      createdAt: true,
    },
  });

  // Prevent timing attacks - always do password comparison
  if (!user) {
    await comparePassword(input.password, '$2a$12$invalidhashfortimingattak');
    throw new UnauthorizedError('Invalid email or password');
  }

  // Check account lockout
  await checkAccountLockout(user);

  if (!user.password) {
    throw new UnauthorizedError('Invalid email or password');
  }

  const isValid = await comparePassword(input.password, user.password);
  if (!isValid) {
    await recordFailedLogin(user.id, user.email);
    throw new UnauthorizedError('Invalid email or password');
  }

  if (!user.isActive) {
    throw new UnauthorizedError('Account is disabled');
  }

  // Reset failed attempts on successful login
  await resetFailedLoginAttempts(user.id);

  await createAuditLog({
    userId: user.id,
    action: 'LOGIN_SUCCESS',
    entity: 'User',
    entityId: user.id,
    metadata: { email: user.email },
  });

  return createSession({
    id: user.id,
    email: user.email,
    name: user.name,
    phone: user.phone,
    avatar: user.avatar,
    role: user.role,
    createdAt: user.createdAt,
  });
}

/**
 * Login/Register with Google OAuth
 */
export async function googleAuth(
  googleUser: {
    id: string;
    email: string;
    name: string;
    picture?: string;
  },
  tokens: {
    accessToken: string;
    refreshToken?: string;
    expiresAt?: number;
  }
): Promise<SessionData> {
  let account = await prisma.account.findUnique({
    where: {
      provider_providerAccountId: {
        provider: 'google',
        providerAccountId: googleUser.id,
      },
    },
    include: { user: true },
  });

  let user: AuthUser;

  if (account) {
    await prisma.account.update({
      where: { id: account.id },
      data: {
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: tokens.expiresAt,
      },
    });

    user = {
      id: account.user.id,
      email: account.user.email,
      name: account.user.name,
      phone: account.user.phone,
      avatar: account.user.avatar,
      role: account.user.role,
      createdAt: account.user.createdAt,
    };

    await createAuditLog({
      userId: user.id,
      action: 'OAUTH_LOGIN',
      entity: 'User',
      entityId: user.id,
      metadata: { provider: 'google' },
    });
  } else {
    const existingUser = await prisma.user.findUnique({
      where: { email: googleUser.email },
    });

    if (existingUser) {
      await prisma.account.create({
        data: {
          userId: existingUser.id,
          type: 'oauth',
          provider: 'google',
          providerAccountId: googleUser.id,
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          expiresAt: tokens.expiresAt,
        },
      });

      user = {
        id: existingUser.id,
        email: existingUser.email,
        name: existingUser.name,
        phone: existingUser.phone,
        avatar: existingUser.avatar || googleUser.picture || null,
        role: existingUser.role,
        createdAt: existingUser.createdAt,
      };

      if (!existingUser.avatar && googleUser.picture) {
        await prisma.user.update({
          where: { id: existingUser.id },
          data: { avatar: googleUser.picture, emailVerified: true },
        });
      }

      await createAuditLog({
        userId: user.id,
        action: 'OAUTH_LINK',
        entity: 'User',
        entityId: user.id,
        metadata: { provider: 'google' },
      });
    } else {
      const newUser = await prisma.user.create({
        data: {
          email: googleUser.email,
          name: googleUser.name,
          avatar: googleUser.picture,
          emailVerified: true,
          accounts: {
            create: {
              type: 'oauth',
              provider: 'google',
              providerAccountId: googleUser.id,
              accessToken: tokens.accessToken,
              refreshToken: tokens.refreshToken,
              expiresAt: tokens.expiresAt,
            },
          },
        },
      });

      user = {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        phone: newUser.phone,
        avatar: newUser.avatar,
        role: newUser.role,
        createdAt: newUser.createdAt,
      };

      await createAuditLog({
        userId: user.id,
        action: 'REGISTER',
        entity: 'User',
        entityId: user.id,
        metadata: { provider: 'google', email: user.email },
      });
    }
  }

  return createSession(user);
}

// ============================================
// Session Management
// ============================================

/**
 * Create a new session for user
 */
async function createSession(user: AuthUser): Promise<SessionData> {
  const token = generateSessionToken();
  const expiresAt = getSessionExpiry();

  await prisma.session.create({
    data: {
      userId: user.id,
      token,
      expiresAt,
    },
  });

  return { user, token, expiresAt };
}

/**
 * Validate session token and return user
 */
export async function validateSession(token: string): Promise<AuthUser | null> {
  const session = await prisma.session.findUnique({
    where: { token },
    include: { user: true },
  });

  if (!session) {
    return null;
  }

  if (session.expiresAt < new Date()) {
    await prisma.session.delete({ where: { id: session.id } });
    return null;
  }

  if (!session.user.isActive) {
    return null;
  }

  await prisma.session.update({
    where: { id: session.id },
    data: { lastActiveAt: new Date() },
  });

  return {
    id: session.user.id,
    email: session.user.email,
    name: session.user.name,
    phone: session.user.phone,
    avatar: session.user.avatar,
    role: session.user.role,
    createdAt: session.user.createdAt,
  };
}

/**
 * Logout - delete session
 */
export async function logout(token: string, userId?: string): Promise<void> {
  await prisma.session.deleteMany({
    where: { token },
  });

  if (userId) {
    await createAuditLog({
      userId,
      action: 'LOGOUT',
      entity: 'User',
      entityId: userId,
    });
  }
}

/**
 * Logout all sessions for a user
 */
export async function logoutAll(userId: string): Promise<void> {
  await prisma.session.deleteMany({
    where: { userId },
  });

  await createAuditLog({
    userId,
    action: 'LOGOUT_ALL',
    entity: 'User',
    entityId: userId,
  });
}

/**
 * Get user sessions
 */
export async function getUserSessions(userId: string) {
  return prisma.session.findMany({
    where: { userId },
    select: {
      id: true,
      createdAt: true,
      lastActiveAt: true,
      userAgent: true,
      ipAddress: true,
    },
    orderBy: { lastActiveAt: 'desc' },
  });
}

/**
 * Delete specific session
 */
export async function deleteSession(userId: string, sessionId: string): Promise<void> {
  await prisma.session.deleteMany({
    where: { id: sessionId, userId },
  });

  await createAuditLog({
    userId,
    action: 'SESSION_DELETED',
    entity: 'Session',
    entityId: sessionId,
  });
}

// ============================================
// Email Verification
// ============================================

/**
 * Generate email verification token
 */
async function generateEmailVerificationToken(userId: string): Promise<string> {
  const token = nanoid(64);
  const expires = new Date(Date.now() + env.EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS * 60 * 60 * 1000);

  // Store hashed token for security
  const hashedToken = await hashPassword(token);

  await prisma.user.update({
    where: { id: userId },
    data: {
      emailVerificationToken: hashedToken,
      emailVerificationExpires: expires,
    },
  });

  return token;
}

/**
 * Verify email with token
 */
export async function verifyEmail(token: string): Promise<void> {
  // Find users with pending verification
  const users = await prisma.user.findMany({
    where: {
      emailVerified: false,
      emailVerificationToken: { not: null },
      emailVerificationExpires: { gt: new Date() },
    },
    select: {
      id: true,
      email: true,
      emailVerificationToken: true,
    },
  });

  // Find matching token
  let matchedUser: { id: string; email: string } | null = null;
  for (const user of users) {
    if (user.emailVerificationToken) {
      const isValid = await comparePassword(token, user.emailVerificationToken);
      if (isValid) {
        matchedUser = user;
        break;
      }
    }
  }

  if (!matchedUser) {
    throw new BadRequestError('Invalid or expired verification token');
  }

  await prisma.user.update({
    where: { id: matchedUser.id },
    data: {
      emailVerified: true,
      emailVerificationToken: null,
      emailVerificationExpires: null,
    },
  });

  await createAuditLog({
    userId: matchedUser.id,
    action: 'EMAIL_VERIFIED',
    entity: 'User',
    entityId: matchedUser.id,
  });
}

/**
 * Resend verification email
 */
export async function resendVerificationEmail(userId: string): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true, email: true, name: true, emailVerified: true },
  });

  if (!user) {
    throw new BadRequestError('User not found');
  }

  if (user.emailVerified) {
    throw new BadRequestError('Email is already verified');
  }

  const token = await generateEmailVerificationToken(user.id);
  await sendVerificationEmail(user.email, user.name, token);

  await createAuditLog({
    userId: user.id,
    action: 'EMAIL_VERIFICATION_SENT',
    entity: 'User',
    entityId: user.id,
  });
}

// ============================================
// Password Reset
// ============================================

/**
 * Request password reset
 */
export async function requestPasswordReset(email: string): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { email },
    select: { id: true, email: true, name: true, password: true },
  });

  // Always return success to prevent email enumeration
  if (!user) {
    return;
  }

  // Only allow password reset for users with password (not OAuth-only)
  if (!user.password) {
    return;
  }

  const token = nanoid(64);
  const expires = new Date(Date.now() + env.PASSWORD_RESET_TOKEN_EXPIRES_HOURS * 60 * 60 * 1000);

  // Store hashed token
  const hashedToken = await hashPassword(token);

  await prisma.user.update({
    where: { id: user.id },
    data: {
      passwordResetToken: hashedToken,
      passwordResetExpires: expires,
    },
  });

  await createAuditLog({
    userId: user.id,
    action: 'PASSWORD_RESET_REQUESTED',
    entity: 'User',
    entityId: user.id,
  });

  await sendPasswordResetEmail(user.email, user.name, token);
}

/**
 * Reset password with token
 */
export async function resetPassword(token: string, newPassword: string): Promise<void> {
  // Find users with valid reset tokens
  const users = await prisma.user.findMany({
    where: {
      passwordResetToken: { not: null },
      passwordResetExpires: { gt: new Date() },
    },
    select: {
      id: true,
      passwordResetToken: true,
    },
  });

  // Find matching token
  let matchedUser: { id: string } | null = null;
  for (const user of users) {
    if (user.passwordResetToken) {
      const isValid = await comparePassword(token, user.passwordResetToken);
      if (isValid) {
        matchedUser = user;
        break;
      }
    }
  }

  if (!matchedUser) {
    throw new BadRequestError('Invalid or expired reset token');
  }

  // Update password and clear reset token
  const hashedPassword = await hashPassword(newPassword);

  await prisma.user.update({
    where: { id: matchedUser.id },
    data: {
      password: hashedPassword,
      passwordResetToken: null,
      passwordResetExpires: null,
      failedLoginAttempts: 0,
      lockedUntil: null,
    },
  });

  // Invalidate all sessions (force re-login)
  await prisma.session.deleteMany({
    where: { userId: matchedUser.id },
  });

  await createAuditLog({
    userId: matchedUser.id,
    action: 'PASSWORD_RESET_COMPLETED',
    entity: 'User',
    entityId: matchedUser.id,
  });
}

/**
 * Change password (for logged-in users)
 */
export async function changePassword(
  userId: string,
  currentPassword: string,
  newPassword: string
): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { password: true },
  });

  if (!user?.password) {
    throw new BadRequestError(
      'Cannot change password for accounts that use only social login'
    );
  }

  const isValid = await comparePassword(currentPassword, user.password);
  if (!isValid) {
    throw new UnauthorizedError('Current password is incorrect');
  }

  const hashedPassword = await hashPassword(newPassword);

  await prisma.user.update({
    where: { id: userId },
    data: { password: hashedPassword },
  });

  await createAuditLog({
    userId,
    action: 'PASSWORD_CHANGED',
    entity: 'User',
    entityId: userId,
  });
}
