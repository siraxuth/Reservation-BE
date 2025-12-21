// Menu Item Service
import { prisma } from '../config/database';
import { NotFoundError, ForbiddenError } from '../utils/errors';
import { parsePagination, createPaginationMeta } from '../utils/response';
import type {
  CreateMenuItemInput,
  UpdateMenuItemInput,
  PaginationInput,
} from '../utils/validation';
import type { Role } from '@prisma/client';

export interface MenuItemResponse {
  id: string;
  vendorId: string;
  name: string;
  description: string | null;
  price: number;
  image: string | null;
  category: string;
  isAvailable: boolean;
  preparationTime: number;
  createdAt: Date;
  updatedAt: Date;
  vendor?: {
    id: string;
    name: string;
    isOpen: boolean;
  };
}

/**
 * Create menu item for a vendor
 */
export async function createMenuItem(
  vendorId: string,
  userId: string,
  userRole: Role,
  input: CreateMenuItemInput
): Promise<MenuItemResponse> {
  const vendor = await prisma.vendor.findUnique({
    where: { id: vendorId },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  // Check permission
  if (vendor.userId !== userId && userRole !== 'ADMIN') {
    throw new ForbiddenError('Not authorized to add menu items to this vendor');
  }

  const menuItem = await prisma.menuItem.create({
    data: {
      vendorId,
      name: input.name,
      description: input.description,
      price: input.price,
      category: input.category,
      preparationTime: input.preparationTime,
      isAvailable: input.isAvailable,
    },
    include: {
      vendor: {
        select: {
          id: true,
          name: true,
          isOpen: true,
        },
      },
    },
  });

  return menuItem;
}

/**
 * Get menu item by ID
 */
export async function getMenuItemById(
  menuItemId: string
): Promise<MenuItemResponse> {
  const menuItem = await prisma.menuItem.findUnique({
    where: { id: menuItemId },
    include: {
      vendor: {
        select: {
          id: true,
          name: true,
          isOpen: true,
        },
      },
    },
  });

  if (!menuItem) {
    throw new NotFoundError('Menu item');
  }

  return menuItem;
}

/**
 * Update menu item
 */
export async function updateMenuItem(
  menuItemId: string,
  userId: string,
  userRole: Role,
  input: UpdateMenuItemInput
): Promise<MenuItemResponse> {
  const menuItem = await prisma.menuItem.findUnique({
    where: { id: menuItemId },
    include: { vendor: true },
  });

  if (!menuItem) {
    throw new NotFoundError('Menu item');
  }

  // Check permission
  if (menuItem.vendor.userId !== userId && userRole !== 'ADMIN') {
    throw new ForbiddenError('Not authorized to update this menu item');
  }

  const updated = await prisma.menuItem.update({
    where: { id: menuItemId },
    data: {
      name: input.name,
      description: input.description,
      price: input.price,
      image: input.image,
      category: input.category,
      preparationTime: input.preparationTime,
      isAvailable: input.isAvailable,
    },
    include: {
      vendor: {
        select: {
          id: true,
          name: true,
          isOpen: true,
        },
      },
    },
  });

  return updated;
}

/**
 * Delete menu item
 */
export async function deleteMenuItem(
  menuItemId: string,
  userId: string,
  userRole: Role
): Promise<void> {
  const menuItem = await prisma.menuItem.findUnique({
    where: { id: menuItemId },
    include: { vendor: true },
  });

  if (!menuItem) {
    throw new NotFoundError('Menu item');
  }

  // Check permission
  if (menuItem.vendor.userId !== userId && userRole !== 'ADMIN') {
    throw new ForbiddenError('Not authorized to delete this menu item');
  }

  await prisma.menuItem.delete({ where: { id: menuItemId } });
}

/**
 * Get menu items for a vendor
 */
export async function getVendorMenuItems(
  vendorId: string,
  pagination: PaginationInput,
  filters?: {
    category?: string;
    isAvailable?: boolean;
    search?: string;
  }
) {
  const { page, limit, skip } = parsePagination(pagination);

  const where: any = { vendorId };

  if (filters?.category) {
    where.category = filters.category;
  }

  if (filters?.isAvailable !== undefined) {
    where.isAvailable = filters.isAvailable;
  }

  if (filters?.search) {
    where.OR = [
      { name: { contains: filters.search, mode: 'insensitive' } },
      { description: { contains: filters.search, mode: 'insensitive' } },
    ];
  }

  const [menuItems, total] = await Promise.all([
    prisma.menuItem.findMany({
      where,
      include: {
        vendor: {
          select: {
            id: true,
            name: true,
            isOpen: true,
          },
        },
      },
      orderBy: [{ category: 'asc' }, { name: 'asc' }],
      skip,
      take: limit,
    }),
    prisma.menuItem.count({ where }),
  ]);

  return {
    items: menuItems,
    meta: createPaginationMeta(page, limit, total),
  };
}

/**
 * Toggle menu item availability
 */
export async function toggleMenuItemAvailability(
  menuItemId: string,
  userId: string,
  userRole: Role
): Promise<MenuItemResponse> {
  const menuItem = await prisma.menuItem.findUnique({
    where: { id: menuItemId },
    include: { vendor: true },
  });

  if (!menuItem) {
    throw new NotFoundError('Menu item');
  }

  // Check permission
  if (menuItem.vendor.userId !== userId && userRole !== 'ADMIN') {
    throw new ForbiddenError('Not authorized to update this menu item');
  }

  const updated = await prisma.menuItem.update({
    where: { id: menuItemId },
    data: { isAvailable: !menuItem.isAvailable },
    include: {
      vendor: {
        select: {
          id: true,
          name: true,
          isOpen: true,
        },
      },
    },
  });

  return updated;
}

/**
 * Get all menu categories for a vendor
 */
export async function getVendorCategories(vendorId: string): Promise<string[]> {
  const menuItems = await prisma.menuItem.findMany({
    where: { vendorId },
    select: { category: true },
    distinct: ['category'],
  });

  return menuItems.map((item) => item.category).sort();
}

/**
 * Bulk update menu item availability
 */
export async function bulkUpdateAvailability(
  vendorId: string,
  userId: string,
  userRole: Role,
  menuItemIds: string[],
  isAvailable: boolean
): Promise<number> {
  const vendor = await prisma.vendor.findUnique({
    where: { id: vendorId },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  // Check permission
  if (vendor.userId !== userId && userRole !== 'ADMIN') {
    throw new ForbiddenError('Not authorized to update menu items');
  }

  const result = await prisma.menuItem.updateMany({
    where: {
      id: { in: menuItemIds },
      vendorId,
    },
    data: { isAvailable },
  });

  return result.count;
}
