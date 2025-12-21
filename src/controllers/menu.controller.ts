// Menu Controller
import { Elysia, t } from 'elysia';
import * as menuService from '../services/menu.service';
import { validateSession, type AuthUser } from '../services/auth.service';
import {
  authPlugin,
  requireAuth,
  requireVendorOrAdmin,
} from '../middlewares/auth.middleware';
import { success, paginated } from '../utils/response';
import {
  createMenuItemSchema,
  updateMenuItemSchema,
  paginationSchema,
} from '../utils/validation';
import { BadRequestError, UnauthorizedError } from '../utils/errors';

// Helper function to extract and validate auth
async function getAuthUser(request: Request): Promise<AuthUser> {
  const authHeader = request.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    throw new UnauthorizedError('Authentication required');
  }

  const token = authHeader.slice(7);
  const user = await validateSession(token);

  if (!user) {
    throw new UnauthorizedError('Invalid or expired session');
  }

  return user;
}

export const menuController = new Elysia({ prefix: '/menu' })
  // Public routes
  .use(authPlugin)

  // Get menu item by ID
  .get(
    '/:menuItemId',
    async ({ params }) => {
      const menuItem = await menuService.getMenuItemById(params.menuItemId);
      return success(menuItem);
    },
    {
      params: t.Object({
        menuItemId: t.String(),
      }),
      detail: {
        tags: ['Menu'],
        summary: 'Get menu item',
        description: 'Get menu item details',
      },
    }
  )

  // Protected routes
  .use(requireAuth)
  .use(requireVendorOrAdmin)

  // Update menu item
  .patch(
    '/:menuItemId',
    async ({ request, params, body }) => {
      const user = await getAuthUser(request);
      const validated = updateMenuItemSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const menuItem = await menuService.updateMenuItem(
        params.menuItemId,
        user.id,
        user.role,
        validated.data
      );
      return success(menuItem, 'Menu item updated');
    },
    {
      params: t.Object({
        menuItemId: t.String(),
      }),
      body: t.Object({
        name: t.Optional(t.String()),
        description: t.Optional(t.String()),
        price: t.Optional(t.Number()),
        image: t.Optional(t.String()),
        category: t.Optional(t.String()),
        preparationTime: t.Optional(t.Number()),
        isAvailable: t.Optional(t.Boolean()),
      }),
      detail: {
        tags: ['Menu'],
        summary: 'Update menu item',
        description: 'Update menu item details',
      },
    }
  )

  // Toggle menu item availability
  .post(
    '/:menuItemId/toggle-availability',
    async ({ request, params }) => {
      const user = await getAuthUser(request);
      const menuItem = await menuService.toggleMenuItemAvailability(
        params.menuItemId,
        user.id,
        user.role
      );
      return success(
        menuItem,
        `Menu item is now ${menuItem.isAvailable ? 'available' : 'unavailable'}`
      );
    },
    {
      params: t.Object({
        menuItemId: t.String(),
      }),
      detail: {
        tags: ['Menu'],
        summary: 'Toggle availability',
        description: 'Toggle menu item availability',
      },
    }
  )

  // Delete menu item
  .delete(
    '/:menuItemId',
    async ({ request, params }) => {
      const user = await getAuthUser(request);
      await menuService.deleteMenuItem(params.menuItemId, user.id, user.role);
      return success(null, 'Menu item deleted');
    },
    {
      params: t.Object({
        menuItemId: t.String(),
      }),
      detail: {
        tags: ['Menu'],
        summary: 'Delete menu item',
        description: 'Delete menu item',
      },
    }
  );

// Vendor Menu Routes (nested under /vendors/:vendorId/menu)
export const vendorMenuController = new Elysia({ prefix: '/vendors/:vendorId/menu' })
  .use(authPlugin)

  // Get vendor's menu items (public)
  .get(
    '/',
    async ({ params, query }) => {
      const pagination = paginationSchema.safeParse(query);
      const paginationData = pagination.success ? pagination.data : { page: 1, limit: 20 };
      const result = await menuService.getVendorMenuItems(
        params.vendorId,
        paginationData,
        {
          category: query.category,
          isAvailable:
            query.isAvailable === 'true'
              ? true
              : query.isAvailable === 'false'
              ? false
              : undefined,
          search: query.search,
        }
      );
      return paginated(result);
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      query: t.Object({
        page: t.Optional(t.String()),
        limit: t.Optional(t.String()),
        category: t.Optional(t.String()),
        isAvailable: t.Optional(t.String()),
        search: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Menu'],
        summary: 'Get vendor menu',
        description: 'Get all menu items for a vendor',
      },
    }
  )

  // Get vendor's menu categories
  .get(
    '/categories',
    async ({ params }) => {
      const categories = await menuService.getVendorCategories(params.vendorId);
      return success(categories);
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      detail: {
        tags: ['Menu'],
        summary: 'Get vendor categories',
        description: 'Get all menu categories for a vendor',
      },
    }
  )

  // Protected routes
  .use(requireAuth)
  .use(requireVendorOrAdmin)

  // Create menu item for vendor
  .post(
    '/',
    async ({ request, params, body }) => {
      const user = await getAuthUser(request);
      const validated = createMenuItemSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const menuItem = await menuService.createMenuItem(
        params.vendorId,
        user.id,
        user.role,
        validated.data
      );
      return success(menuItem, 'Menu item created');
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      body: t.Object({
        name: t.String(),
        description: t.Optional(t.String()),
        price: t.Number(),
        category: t.String(),
        preparationTime: t.Optional(t.Number()),
        isAvailable: t.Optional(t.Boolean()),
      }),
      detail: {
        tags: ['Menu'],
        summary: 'Create menu item',
        description: 'Create a new menu item for vendor',
      },
    }
  )

  // Bulk update availability
  .post(
    '/bulk-availability',
    async ({ request, params, body }) => {
      const user = await getAuthUser(request);
      const count = await menuService.bulkUpdateAvailability(
        params.vendorId,
        user.id,
        user.role,
        body.menuItemIds,
        body.isAvailable
      );
      return success({ updatedCount: count }, `${count} menu items updated`);
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      body: t.Object({
        menuItemIds: t.Array(t.String()),
        isAvailable: t.Boolean(),
      }),
      detail: {
        tags: ['Menu'],
        summary: 'Bulk update availability',
        description: 'Update availability for multiple menu items',
      },
    }
  );
