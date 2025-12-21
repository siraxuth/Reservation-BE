// Review Service
import { prisma } from '../config/database';
import { NotFoundError, ForbiddenError, BadRequestError } from '../utils/errors';
import { parsePagination, createPaginationMeta } from '../utils/response';
import type { PaginationInput } from '../utils/validation';
import type { Role } from '@prisma/client';

export interface ReviewResponse {
  id: string;
  userId: string;
  vendorId: string;
  rating: number;
  comment: string | null;
  images: string[];
  createdAt: Date;
  updatedAt: Date;
  user?: {
    id: string;
    name: string;
    avatar: string | null;
  };
  vendor?: {
    id: string;
    name: string;
    image: string | null;
  };
}

export interface CreateReviewInput {
  vendorId: string;
  rating: number;
  comment?: string;
  images?: string[];
}

export interface UpdateReviewInput {
  rating?: number;
  comment?: string;
  images?: string[];
}

export interface ReviewStats {
  averageRating: number;
  totalReviews: number;
  ratingDistribution: {
    1: number;
    2: number;
    3: number;
    4: number;
    5: number;
  };
}

/**
 * Create a new review
 */
export async function createReview(
  userId: string,
  input: CreateReviewInput
): Promise<ReviewResponse> {
  // Validate rating
  if (input.rating < 1 || input.rating > 5) {
    throw new BadRequestError('Rating must be between 1 and 5');
  }

  // Check if vendor exists
  const vendor = await prisma.vendor.findUnique({
    where: { id: input.vendorId },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  // Check if user has completed a reservation with this vendor
  const hasCompletedReservation = await prisma.reservation.findFirst({
    where: {
      customerId: userId,
      vendorId: input.vendorId,
      status: 'COMPLETED',
    },
  });

  if (!hasCompletedReservation) {
    throw new BadRequestError('You can only review vendors you have ordered from');
  }

  // Check if user already reviewed this vendor
  const existingReview = await prisma.review.findFirst({
    where: {
      userId,
      vendorId: input.vendorId,
    },
  });

  if (existingReview) {
    throw new BadRequestError('You have already reviewed this vendor');
  }

  // Create review
  const review = await prisma.review.create({
    data: {
      userId,
      vendorId: input.vendorId,
      rating: input.rating,
      comment: input.comment,
      images: input.images || [],
    },
    include: {
      user: {
        select: {
          id: true,
          name: true,
          avatar: true,
        },
      },
      vendor: {
        select: {
          id: true,
          name: true,
          image: true,
        },
      },
    },
  });

  // Update vendor rating
  await updateVendorRating(input.vendorId);

  return review;
}

/**
 * Update an existing review
 */
export async function updateReview(
  reviewId: string,
  userId: string,
  userRole: Role,
  input: UpdateReviewInput
): Promise<ReviewResponse> {
  const review = await prisma.review.findUnique({
    where: { id: reviewId },
  });

  if (!review) {
    throw new NotFoundError('Review');
  }

  // Check permission
  if (review.userId !== userId && userRole !== 'ADMIN') {
    throw new ForbiddenError('Not authorized to update this review');
  }

  // Validate rating if provided
  if (input.rating !== undefined && (input.rating < 1 || input.rating > 5)) {
    throw new BadRequestError('Rating must be between 1 and 5');
  }

  const updated = await prisma.review.update({
    where: { id: reviewId },
    data: {
      rating: input.rating,
      comment: input.comment,
      images: input.images,
    },
    include: {
      user: {
        select: {
          id: true,
          name: true,
          avatar: true,
        },
      },
      vendor: {
        select: {
          id: true,
          name: true,
          image: true,
        },
      },
    },
  });

  // Update vendor rating if rating changed
  if (input.rating !== undefined) {
    await updateVendorRating(review.vendorId);
  }

  return updated;
}

/**
 * Delete a review
 */
export async function deleteReview(
  reviewId: string,
  userId: string,
  userRole: Role
): Promise<void> {
  const review = await prisma.review.findUnique({
    where: { id: reviewId },
  });

  if (!review) {
    throw new NotFoundError('Review');
  }

  // Check permission
  if (review.userId !== userId && userRole !== 'ADMIN') {
    throw new ForbiddenError('Not authorized to delete this review');
  }

  await prisma.review.delete({
    where: { id: reviewId },
  });

  // Update vendor rating
  await updateVendorRating(review.vendorId);
}

/**
 * Get review by ID
 */
export async function getReviewById(reviewId: string): Promise<ReviewResponse> {
  const review = await prisma.review.findUnique({
    where: { id: reviewId },
    include: {
      user: {
        select: {
          id: true,
          name: true,
          avatar: true,
        },
      },
      vendor: {
        select: {
          id: true,
          name: true,
          image: true,
        },
      },
    },
  });

  if (!review) {
    throw new NotFoundError('Review');
  }

  return review;
}

/**
 * Get reviews for a vendor
 */
export async function getVendorReviews(
  vendorId: string,
  pagination: PaginationInput,
  filters?: {
    rating?: number;
    sortBy?: 'newest' | 'oldest' | 'highest' | 'lowest';
  }
) {
  const { page, limit, skip } = parsePagination(pagination);

  const where: any = { vendorId };

  if (filters?.rating) {
    where.rating = filters.rating;
  }

  // Determine sort order
  let orderBy: any = { createdAt: 'desc' };
  if (filters?.sortBy === 'oldest') {
    orderBy = { createdAt: 'asc' };
  } else if (filters?.sortBy === 'highest') {
    orderBy = { rating: 'desc' };
  } else if (filters?.sortBy === 'lowest') {
    orderBy = { rating: 'asc' };
  }

  const [reviews, total] = await Promise.all([
    prisma.review.findMany({
      where,
      include: {
        user: {
          select: {
            id: true,
            name: true,
            avatar: true,
          },
        },
      },
      orderBy,
      skip,
      take: limit,
    }),
    prisma.review.count({ where }),
  ]);

  return {
    items: reviews,
    meta: createPaginationMeta(page, limit, total),
  };
}

/**
 * Get user's reviews
 */
export async function getUserReviews(
  userId: string,
  pagination: PaginationInput
) {
  const { page, limit, skip } = parsePagination(pagination);

  const [reviews, total] = await Promise.all([
    prisma.review.findMany({
      where: { userId },
      include: {
        vendor: {
          select: {
            id: true,
            name: true,
            image: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.review.count({ where: { userId } }),
  ]);

  return {
    items: reviews,
    meta: createPaginationMeta(page, limit, total),
  };
}

/**
 * Get all reviews (admin)
 */
export async function getAllReviews(
  pagination: PaginationInput,
  filters?: {
    vendorId?: string;
    userId?: string;
    rating?: number;
  }
) {
  const { page, limit, skip } = parsePagination(pagination);

  const where: any = {};

  if (filters?.vendorId) {
    where.vendorId = filters.vendorId;
  }
  if (filters?.userId) {
    where.userId = filters.userId;
  }
  if (filters?.rating) {
    where.rating = filters.rating;
  }

  const [reviews, total] = await Promise.all([
    prisma.review.findMany({
      where,
      include: {
        user: {
          select: {
            id: true,
            name: true,
            avatar: true,
          },
        },
        vendor: {
          select: {
            id: true,
            name: true,
            image: true,
          },
        },
      },
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    }),
    prisma.review.count({ where }),
  ]);

  return {
    items: reviews,
    meta: createPaginationMeta(page, limit, total),
  };
}

/**
 * Get review statistics for a vendor
 */
export async function getVendorReviewStats(vendorId: string): Promise<ReviewStats> {
  const reviews = await prisma.review.findMany({
    where: { vendorId },
    select: { rating: true },
  });

  const totalReviews = reviews.length;

  if (totalReviews === 0) {
    return {
      averageRating: 0,
      totalReviews: 0,
      ratingDistribution: { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 },
    };
  }

  const ratingSum = reviews.reduce((sum, r) => sum + r.rating, 0);
  const averageRating = Math.round((ratingSum / totalReviews) * 10) / 10;

  const ratingDistribution = {
    1: reviews.filter((r) => r.rating === 1).length,
    2: reviews.filter((r) => r.rating === 2).length,
    3: reviews.filter((r) => r.rating === 3).length,
    4: reviews.filter((r) => r.rating === 4).length,
    5: reviews.filter((r) => r.rating === 5).length,
  };

  return {
    averageRating,
    totalReviews,
    ratingDistribution,
  };
}

/**
 * Get recent reviews (for homepage)
 */
export async function getRecentReviews(limit: number = 10) {
  const reviews = await prisma.review.findMany({
    where: {
      rating: { gte: 4 }, // Only show good reviews on homepage
    },
    include: {
      user: {
        select: {
          id: true,
          name: true,
          avatar: true,
        },
      },
      vendor: {
        select: {
          id: true,
          name: true,
          image: true,
        },
      },
    },
    orderBy: { createdAt: 'desc' },
    take: limit,
  });

  return reviews;
}

/**
 * Check if user can review a vendor
 */
export async function canUserReviewVendor(
  userId: string,
  vendorId: string
): Promise<{ canReview: boolean; reason?: string }> {
  // Check if user has completed a reservation
  const hasCompletedReservation = await prisma.reservation.findFirst({
    where: {
      customerId: userId,
      vendorId,
      status: 'COMPLETED',
    },
  });

  if (!hasCompletedReservation) {
    return {
      canReview: false,
      reason: 'You need to complete an order before reviewing',
    };
  }

  // Check if already reviewed
  const existingReview = await prisma.review.findFirst({
    where: { userId, vendorId },
  });

  if (existingReview) {
    return {
      canReview: false,
      reason: 'You have already reviewed this vendor',
    };
  }

  return { canReview: true };
}

/**
 * Update vendor's average rating
 */
async function updateVendorRating(vendorId: string): Promise<void> {
  const stats = await getVendorReviewStats(vendorId);

  await prisma.vendor.update({
    where: { id: vendorId },
    data: { rating: stats.averageRating },
  });
}

/**
 * Get top rated vendors
 */
export async function getTopRatedVendors(limit: number = 5) {
  const vendors = await prisma.vendor.findMany({
    where: {
      isOpen: true,
      rating: { gt: 0 },
    },
    include: {
      _count: {
        select: { reviews: true },
      },
    },
    orderBy: [{ rating: 'desc' }, { totalOrders: 'desc' }],
    take: limit,
  });

  return vendors.map((v) => ({
    id: v.id,
    name: v.name,
    image: v.image,
    rating: v.rating,
    totalReviews: v._count.reviews,
    totalOrders: v.totalOrders,
  }));
}
