// User Service
import { prisma } from '../config/database';
import { NotFoundError, ConflictError } from '../utils/errors';
import { parsePagination, createPaginationMeta } from '../utils/response';
import type { UpdateProfileInput, PaginationInput } from '../utils/validation';
import type { Role } from '@prisma/client';

export interface UserResponse {
  id: string;
  email: string;
  name: string;
  phone: string | null;
  avatar: string | null;
  role: Role;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Get user by ID
 */
export async function getUserById(userId: string): Promise<UserResponse> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      name: true,
      phone: true,
      avatar: true,
      role: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  if (!user) {
    throw new NotFoundError('User');
  }

  return user;
}

/**
 * Update user profile
 */
export async function updateProfile(
  userId: string,
  input: UpdateProfileInput
): Promise<UserResponse> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new NotFoundError('User');
  }

  const updated = await prisma.user.update({
    where: { id: userId },
    data: {
      name: input.name,
      phone: input.phone,
      avatar: input.avatar,
    },
    select: {
      id: true,
      email: true,
      name: true,
      phone: true,
      avatar: true,
      role: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  return updated;
}

/**
 * Get all users (admin only)
 */
export async function getAllUsers(
  pagination: PaginationInput,
  filters?: {
    role?: Role;
    search?: string;
    isActive?: boolean;
  }
) {
  const { page, limit, skip } = parsePagination(pagination);

  const where: any = {};

  if (filters?.role) {
    where.role = filters.role;
  }

  if (filters?.isActive !== undefined) {
    where.isActive = filters.isActive;
  }

  if (filters?.search) {
    where.OR = [
      { name: { contains: filters.search, mode: 'insensitive' } },
      { email: { contains: filters.search, mode: 'insensitive' } },
    ];
  }

  const [users, total] = await Promise.all([
    prisma.user.findMany({
      where,
      select: {
        id: true,
        email: true,
        name: true,
        phone: true,
        avatar: true,
        role: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.user.count({ where }),
  ]);

  return {
    items: users,
    meta: createPaginationMeta(page, limit, total),
  };
}

/**
 * Update user role (admin only)
 */
export async function updateUserRole(
  userId: string,
  role: Role
): Promise<UserResponse> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new NotFoundError('User');
  }

  const updated = await prisma.user.update({
    where: { id: userId },
    data: { role },
    select: {
      id: true,
      email: true,
      name: true,
      phone: true,
      avatar: true,
      role: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  return updated;
}

/**
 * Toggle user active status (admin only)
 */
export async function toggleUserStatus(userId: string): Promise<UserResponse> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new NotFoundError('User');
  }

  const updated = await prisma.user.update({
    where: { id: userId },
    data: { isActive: !user.isActive },
    select: {
      id: true,
      email: true,
      name: true,
      phone: true,
      avatar: true,
      role: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  return updated;
}

/**
 * Delete user (admin only)
 */
export async function deleteUser(userId: string): Promise<void> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new NotFoundError('User');
  }

  await prisma.user.delete({
    where: { id: userId },
  });
}

/**
 * Update user password (admin only)
 */
export async function updateUserPassword(
  userId: string,
  newPassword: string
): Promise<UserResponse> {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new NotFoundError('User');
  }

  // Hash the new password
  const hashedPassword = await Bun.password.hash(newPassword, {
    algorithm: 'bcrypt',
    cost: 10,
  });

  const updated = await prisma.user.update({
    where: { id: userId },
    data: { password: hashedPassword },
    select: {
      id: true,
      email: true,
      name: true,
      phone: true,
      avatar: true,
      role: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  return updated;
}

/**
 * Get user statistics
 */
export async function getUserStats() {
  const [total, customers, vendors, admins, active, inactive] =
    await Promise.all([
      prisma.user.count(),
      prisma.user.count({ where: { role: 'CUSTOMER' } }),
      prisma.user.count({ where: { role: 'VENDOR' } }),
      prisma.user.count({ where: { role: 'ADMIN' } }),
      prisma.user.count({ where: { isActive: true } }),
      prisma.user.count({ where: { isActive: false } }),
    ]);

  return {
    total,
    byRole: { customers, vendors, admins },
    byStatus: { active, inactive },
  };
}
