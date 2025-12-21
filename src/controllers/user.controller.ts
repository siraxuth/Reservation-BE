// User Controller
import { Elysia, t } from 'elysia';
import { bearer } from '@elysiajs/bearer';
import * as userService from '../services/user.service';
import { validateSession, type AuthUser } from '../services/auth.service';
import { success, paginated } from '../utils/response';
import { updateProfileSchema, paginationSchema } from '../utils/validation';
import { BadRequestError, UnauthorizedError, ForbiddenError } from '../utils/errors';

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

// Helper function to require admin role
async function getAdminUser(request: Request): Promise<AuthUser> {
  const user = await getAuthUser(request);
  if (user.role !== 'ADMIN') {
    throw new ForbiddenError('Admin access required');
  }
  return user;
}

export const userController = new Elysia({ prefix: '/users' })
  .use(bearer())

  // Get current user profile
  .get(
    '/me',
    async ({ request }) => {
      const user = await getAuthUser(request);
      const profile = await userService.getUserById(user.id);
      return success(profile);
    },
    {
      detail: {
        tags: ['Users'],
        summary: 'Get my profile',
        description: 'Get current user profile',
      },
    }
  )

  // Update current user profile
  .patch(
    '/me',
    async ({ request, body }) => {
      const user = await getAuthUser(request);
      const validated = updateProfileSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const profile = await userService.updateProfile(user.id, validated.data);
      return success(profile, 'Profile updated');
    },
    {
      body: t.Object({
        name: t.Optional(t.String()),
        phone: t.Optional(t.String()),
        avatar: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Users'],
        summary: 'Update my profile',
        description: 'Update current user profile',
      },
    }
  )

  // Get user stats (admin) - must be before /:userId to avoid route conflict
  .get(
    '/stats/overview',
    async ({ request }) => {
      await getAdminUser(request);
      const stats = await userService.getUserStats();
      return success(stats);
    },
    {
      detail: {
        tags: ['Users'],
        summary: 'Get user statistics',
        description: 'Get user statistics (admin only)',
      },
    }
  )

  // Get all users (admin)
  .get(
    '/',
    async ({ request, query }) => {
      await getAdminUser(request);
      const pagination = paginationSchema.safeParse(query);
      const paginationData = pagination.success ? pagination.data : { page: 1, limit: 20 };
      const result = await userService.getAllUsers(
        paginationData,
        {
          role: query.role as any,
          search: query.search,
          isActive: query.isActive === 'true' ? true : query.isActive === 'false' ? false : undefined,
        }
      );
      return paginated(result);
    },
    {
      query: t.Object({
        page: t.Optional(t.String()),
        limit: t.Optional(t.String()),
        role: t.Optional(t.String()),
        search: t.Optional(t.String()),
        isActive: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Users'],
        summary: 'List all users',
        description: 'Get all users (admin only)',
      },
    }
  )

  // Get user by ID (admin)
  .get(
    '/:userId',
    async ({ request, params }) => {
      await getAdminUser(request);
      const user = await userService.getUserById(params.userId);
      return success(user);
    },
    {
      params: t.Object({
        userId: t.String(),
      }),
      detail: {
        tags: ['Users'],
        summary: 'Get user by ID',
        description: 'Get user details by ID (admin only)',
      },
    }
  )

  // Update user role (admin)
  .patch(
    '/:userId/role',
    async ({ request, params, body }) => {
      await getAdminUser(request);
      const user = await userService.updateUserRole(params.userId, body.role as any);
      return success(user, 'Role updated');
    },
    {
      params: t.Object({
        userId: t.String(),
      }),
      body: t.Object({
        role: t.Union([
          t.Literal('CUSTOMER'),
          t.Literal('VENDOR'),
          t.Literal('ADMIN'),
        ]),
      }),
      detail: {
        tags: ['Users'],
        summary: 'Update user role',
        description: 'Update user role (admin only)',
      },
    }
  )

  // Toggle user status (admin)
  .patch(
    '/:userId/toggle-status',
    async ({ request, params }) => {
      await getAdminUser(request);
      const user = await userService.toggleUserStatus(params.userId);
      return success(user, `User ${user.isActive ? 'activated' : 'deactivated'}`);
    },
    {
      params: t.Object({
        userId: t.String(),
      }),
      detail: {
        tags: ['Users'],
        summary: 'Toggle user status',
        description: 'Activate/deactivate user (admin only)',
      },
    }
  )

  // Update user password (admin)
  .patch(
    '/:userId/password',
    async ({ request, params, body }) => {
      await getAdminUser(request);
      if (!body.password || body.password.length < 6) {
        throw new BadRequestError('Password must be at least 6 characters');
      }
      const user = await userService.updateUserPassword(params.userId, body.password);
      return success(user, 'Password updated');
    },
    {
      params: t.Object({
        userId: t.String(),
      }),
      body: t.Object({
        password: t.String(),
      }),
      detail: {
        tags: ['Users'],
        summary: 'Update user password',
        description: 'Update user password (admin only)',
      },
    }
  )

  // Delete user (admin)
  .delete(
    '/:userId',
    async ({ request, params }) => {
      await getAdminUser(request);
      await userService.deleteUser(params.userId);
      return success(null, 'User deleted');
    },
    {
      params: t.Object({
        userId: t.String(),
      }),
      detail: {
        tags: ['Users'],
        summary: 'Delete user',
        description: 'Delete user (admin only)',
      },
    }
  );
