// Standard API Response Utilities

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  code?: string;
  meta?: {
    page?: number;
    limit?: number;
    total?: number;
    totalPages?: number;
  };
}

export interface PaginationParams {
  page?: number;
  limit?: number;
}

export interface PaginatedResult<T> {
  items: T[];
  meta: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

/**
 * Create success response
 */
export function success<T>(data: T, message?: string): ApiResponse<T> {
  return {
    success: true,
    data,
    message,
  };
}

/**
 * Create paginated success response
 */
export function paginated<T>(result: PaginatedResult<T>): ApiResponse<T[]> {
  return {
    success: true,
    data: result.items,
    meta: result.meta,
  };
}

/**
 * Create error response
 */
export function error(
  message: string,
  code?: string,
  statusCode: number = 400
): Response {
  return new Response(
    JSON.stringify({
      success: false,
      error: message,
      code,
    }),
    {
      status: statusCode,
      headers: { 'Content-Type': 'application/json' },
    }
  );
}

/**
 * Parse pagination params
 */
export function parsePagination(params: PaginationParams): {
  page: number;
  limit: number;
  skip: number;
} {
  const page = Math.max(1, params.page || 1);
  const limit = Math.min(100, Math.max(1, params.limit || 20));
  const skip = (page - 1) * limit;

  return { page, limit, skip };
}

/**
 * Create pagination meta
 */
export function createPaginationMeta(
  page: number,
  limit: number,
  total: number
) {
  return {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  };
}
