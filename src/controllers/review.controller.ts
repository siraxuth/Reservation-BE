// Review Controller
import { Elysia, t } from 'elysia';
import { bearer } from '@elysiajs/bearer';
import * as reviewService from '../services/review.service';
import { validateSession, type AuthUser } from '../services/auth.service';
import { requireAuth, requireAdmin } from '../middlewares/auth.middleware';
import { success, paginated } from '../utils/response';
import { paginationSchema } from '../utils/validation';
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

// Optional auth - returns user if authenticated, null otherwise
async function getOptionalAuthUser(request: Request): Promise<AuthUser | null> {
  try {
    return await getAuthUser(request);
  } catch {
    return null;
  }
}

export const reviewController = new Elysia({ prefix: '/reviews' })
  .use(bearer())

  // Get recent reviews (public - for homepage)
  .get(
    '/recent',
    async ({ query }) => {
      const limit = query.limit ? parseInt(query.limit) : 10;
      const reviews = await reviewService.getRecentReviews(limit);
      return success(reviews);
    },
    {
      query: t.Object({
        limit: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Get recent reviews',
        description: 'Get recent positive reviews for homepage',
      },
    }
  )

  // Get top rated vendors (public)
  .get(
    '/top-vendors',
    async ({ query }) => {
      const limit = query.limit ? parseInt(query.limit) : 5;
      const vendors = await reviewService.getTopRatedVendors(limit);
      return success(vendors);
    },
    {
      query: t.Object({
        limit: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Get top rated vendors',
        description: 'Get vendors with highest ratings',
      },
    }
  )

  // Get review by ID (public)
  .get(
    '/:reviewId',
    async ({ params }) => {
      const review = await reviewService.getReviewById(params.reviewId);
      return success(review);
    },
    {
      params: t.Object({
        reviewId: t.String(),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Get review',
        description: 'Get review details',
      },
    }
  )

  // Create review (authenticated)
  .post(
    '/',
    async ({ request, body }) => {
      const user = await getAuthUser(request);

      if (!body.vendorId || !body.rating) {
        throw new BadRequestError('Vendor ID and rating are required');
      }

      const review = await reviewService.createReview(user.id, {
        vendorId: body.vendorId,
        rating: body.rating,
        comment: body.comment,
        images: body.images,
      });

      return success(review, 'Review created successfully');
    },
    {
      body: t.Object({
        vendorId: t.String(),
        rating: t.Number({ minimum: 1, maximum: 5 }),
        comment: t.Optional(t.String()),
        images: t.Optional(t.Array(t.String())),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Create review',
        description: 'Create a new review for a vendor',
      },
    }
  )

  // Update review (authenticated)
  .patch(
    '/:reviewId',
    async ({ request, params, body }) => {
      const user = await getAuthUser(request);

      const review = await reviewService.updateReview(
        params.reviewId,
        user.id,
        user.role,
        body
      );

      return success(review, 'Review updated successfully');
    },
    {
      params: t.Object({
        reviewId: t.String(),
      }),
      body: t.Object({
        rating: t.Optional(t.Number({ minimum: 1, maximum: 5 })),
        comment: t.Optional(t.String()),
        images: t.Optional(t.Array(t.String())),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Update review',
        description: 'Update an existing review',
      },
    }
  )

  // Delete review (authenticated)
  .delete(
    '/:reviewId',
    async ({ request, params }) => {
      const user = await getAuthUser(request);

      await reviewService.deleteReview(params.reviewId, user.id, user.role);

      return success(null, 'Review deleted successfully');
    },
    {
      params: t.Object({
        reviewId: t.String(),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Delete review',
        description: 'Delete a review',
      },
    }
  )

  // Get my reviews (authenticated)
  .get(
    '/me',
    async ({ request, query }) => {
      const user = await getAuthUser(request);

      const pagination = paginationSchema.safeParse(query);
      const paginationData = pagination.success ? pagination.data : { page: 1, limit: 20 };

      const result = await reviewService.getUserReviews(user.id, paginationData);
      return paginated(result);
    },
    {
      query: t.Object({
        page: t.Optional(t.String()),
        limit: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Get my reviews',
        description: 'Get current user reviews',
      },
    }
  )

  // Check if user can review vendor (authenticated)
  .get(
    '/can-review/:vendorId',
    async ({ request, params }) => {
      const user = await getAuthUser(request);
      const result = await reviewService.canUserReviewVendor(user.id, params.vendorId);
      return success(result);
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Check if can review',
        description: 'Check if current user can review a vendor',
      },
    }
  )

  // Admin routes
  .use(requireAdmin)

  // Get all reviews (admin)
  .get(
    '/',
    async ({ query }) => {
      const pagination = paginationSchema.safeParse(query);
      const paginationData = pagination.success ? pagination.data : { page: 1, limit: 20 };

      const result = await reviewService.getAllReviews(paginationData, {
        vendorId: query.vendorId,
        userId: query.userId,
        rating: query.rating ? parseInt(query.rating) : undefined,
      });

      return paginated(result);
    },
    {
      query: t.Object({
        page: t.Optional(t.String()),
        limit: t.Optional(t.String()),
        vendorId: t.Optional(t.String()),
        userId: t.Optional(t.String()),
        rating: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Get all reviews',
        description: 'Get all reviews (admin only)',
      },
    }
  );

// Vendor Reviews Routes (nested under vendors)
export const vendorReviewsController = new Elysia({
  prefix: '/vendors/:vendorId/reviews',
})
  .use(bearer())

  // Get vendor reviews (public)
  .get(
    '/',
    async ({ params, query }) => {
      const pagination = paginationSchema.safeParse(query);
      const paginationData = pagination.success ? pagination.data : { page: 1, limit: 20 };

      const result = await reviewService.getVendorReviews(
        params.vendorId,
        paginationData,
        {
          rating: query.rating ? parseInt(query.rating) : undefined,
          sortBy: query.sortBy as any,
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
        rating: t.Optional(t.String()),
        sortBy: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Get vendor reviews',
        description: 'Get all reviews for a vendor',
      },
    }
  )

  // Get vendor review stats (public)
  .get(
    '/stats',
    async ({ params }) => {
      const stats = await reviewService.getVendorReviewStats(params.vendorId);
      return success(stats);
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      detail: {
        tags: ['Reviews'],
        summary: 'Get vendor review stats',
        description: 'Get review statistics for a vendor',
      },
    }
  );
