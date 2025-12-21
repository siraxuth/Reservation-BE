// Vendor Service
import { prisma } from '../config/database';
import { NotFoundError, ForbiddenError, ConflictError } from '../utils/errors';
import { parsePagination, createPaginationMeta } from '../utils/response';
import type {
  CreateVendorInput,
  UpdateVendorInput,
  PaginationInput,
} from '../utils/validation';
import type { Role } from '@prisma/client';

export interface VendorResponse {
  id: string;
  userId: string;
  name: string;
  description: string | null;
  image: string | null;
  rating: number;
  totalOrders: number;
  isOpen: boolean;
  categories: string[];
  createdAt: Date;
  updatedAt: Date;
  user?: {
    id: string;
    email: string;
    name: string;
    avatar: string | null;
  };
}

/**
 * Create vendor for a user
 */
export async function createVendor(
  userId: string,
  input: CreateVendorInput
): Promise<VendorResponse> {
  // Check if user already has a vendor
  const existingVendor = await prisma.vendor.findUnique({
    where: { userId },
  });

  if (existingVendor) {
    throw new ConflictError('User already has a vendor profile');
  }

  // Create vendor and update user role
  const [vendor] = await prisma.$transaction([
    prisma.vendor.create({
      data: {
        userId,
        name: input.name,
        description: input.description,
        categories: input.categories,
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            name: true,
            avatar: true,
          },
        },
      },
    }),
    prisma.user.update({
      where: { id: userId },
      data: { role: 'VENDOR' },
    }),
  ]);

  return vendor;
}

/**
 * Get vendor by ID
 */
export async function getVendorById(vendorId: string): Promise<VendorResponse> {
  const vendor = await prisma.vendor.findUnique({
    where: { id: vendorId },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          name: true,
          avatar: true,
        },
      },
    },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  return vendor;
}

/**
 * Get vendor by user ID
 */
export async function getVendorByUserId(userId: string): Promise<VendorResponse> {
  const vendor = await prisma.vendor.findUnique({
    where: { userId },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          name: true,
          avatar: true,
        },
      },
    },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  return vendor;
}

/**
 * Update vendor
 */
export async function updateVendor(
  vendorId: string,
  userId: string,
  userRole: Role,
  input: UpdateVendorInput
): Promise<VendorResponse> {
  const vendor = await prisma.vendor.findUnique({
    where: { id: vendorId },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  // Check permission - vendor owner or admin
  if (vendor.userId !== userId && userRole !== 'ADMIN') {
    throw new ForbiddenError('Not authorized to update this vendor');
  }

  const updated = await prisma.vendor.update({
    where: { id: vendorId },
    data: {
      name: input.name,
      description: input.description,
      image: input.image,
      isOpen: input.isOpen,
      categories: input.categories,
    },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          name: true,
          avatar: true,
        },
      },
    },
  });

  return updated;
}

/**
 * Get all vendors with pagination and filters
 */
export async function getAllVendors(
  pagination: PaginationInput,
  filters?: {
    isOpen?: boolean;
    category?: string;
    search?: string;
  }
) {
  const { page, limit, skip } = parsePagination(pagination);

  const where: any = {};

  if (filters?.isOpen !== undefined) {
    where.isOpen = filters.isOpen;
  }

  if (filters?.category) {
    where.categories = { has: filters.category };
  }

  if (filters?.search) {
    where.OR = [
      { name: { contains: filters.search, mode: 'insensitive' } },
      { description: { contains: filters.search, mode: 'insensitive' } },
    ];
  }

  const [vendors, total] = await Promise.all([
    prisma.vendor.findMany({
      where,
      include: {
        user: {
          select: {
            id: true,
            email: true,
            name: true,
            avatar: true,
          },
        },
      },
      orderBy: [{ rating: 'desc' }, { totalOrders: 'desc' }],
      skip,
      take: limit,
    }),
    prisma.vendor.count({ where }),
  ]);

  return {
    items: vendors,
    meta: createPaginationMeta(page, limit, total),
  };
}

/**
 * Toggle vendor open/close status
 */
export async function toggleVendorStatus(
  vendorId: string,
  userId: string,
  userRole: Role
): Promise<VendorResponse> {
  const vendor = await prisma.vendor.findUnique({
    where: { id: vendorId },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  if (vendor.userId !== userId && userRole !== 'ADMIN') {
    throw new ForbiddenError('Not authorized to update this vendor');
  }

  const updated = await prisma.vendor.update({
    where: { id: vendorId },
    data: { isOpen: !vendor.isOpen },
    include: {
      user: {
        select: {
          id: true,
          email: true,
          name: true,
          avatar: true,
        },
      },
    },
  });

  return updated;
}

/**
 * Delete vendor (admin only)
 */
export async function deleteVendor(vendorId: string): Promise<void> {
  const vendor = await prisma.vendor.findUnique({
    where: { id: vendorId },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  await prisma.$transaction([
    prisma.vendor.delete({ where: { id: vendorId } }),
    prisma.user.update({
      where: { id: vendor.userId },
      data: { role: 'CUSTOMER' },
    }),
  ]);
}

/**
 * Get vendor statistics
 */
export async function getVendorStats(vendorId: string) {
  const vendor = await prisma.vendor.findUnique({
    where: { id: vendorId },
    include: {
      _count: {
        select: {
          menuItems: true,
          reservations: true,
          reviews: true,
        },
      },
      reservations: {
        where: {
          createdAt: {
            gte: new Date(new Date().setHours(0, 0, 0, 0)),
          },
        },
        select: { status: true, totalAmount: true },
      },
    },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  const todayReservations = vendor.reservations;
  const todayRevenue = todayReservations
    .filter((r) => r.status === 'COMPLETED')
    .reduce((sum, r) => sum + r.totalAmount, 0);

  return {
    menuItemsCount: vendor._count.menuItems,
    totalReservations: vendor._count.reservations,
    reviewsCount: vendor._count.reviews,
    rating: vendor.rating,
    totalOrders: vendor.totalOrders,
    today: {
      reservations: todayReservations.length,
      revenue: todayRevenue,
      pending: todayReservations.filter((r) => r.status === 'PENDING').length,
      preparing: todayReservations.filter((r) => r.status === 'PREPARING').length,
      completed: todayReservations.filter((r) => r.status === 'COMPLETED').length,
    },
  };
}

/**
 * Get all categories from all vendors
 */
export async function getAllCategories(): Promise<string[]> {
  const vendors = await prisma.vendor.findMany({
    select: { categories: true },
  });

  const allCategories = vendors.flatMap((v) => v.categories);
  return [...new Set(allCategories)].sort();
}
