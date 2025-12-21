// Validation Schemas using Zod
import { z } from 'zod';

// ===========================================
// Common Schemas
// ===========================================

export const idSchema = z.string().min(1, 'ID is required');

export const paginationSchema = z.object({
  page: z.coerce.number().int().positive().optional().default(1),
  limit: z.coerce.number().int().positive().max(100).optional().default(20),
});

export const emailSchema = z.string().email('Invalid email format');

export const phoneSchema = z
  .string()
  .regex(/^[0-9]{9,10}$/, 'Phone must be 9-10 digits')
  .optional();

// ===========================================
// Auth Schemas
// ===========================================

// Strong password validation result
export interface PasswordValidationResult {
  valid: boolean;
  errors: string[];
  strength: 'weak' | 'fair' | 'good' | 'strong';
}

// Validate strong password with detailed feedback
export function validateStrongPassword(password: string): PasswordValidationResult {
  const errors: string[] = [];

  if (password.length < 12) {
    errors.push('Password must be at least 12 characters long');
  }

  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }

  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }

  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }

  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push('Password must contain at least one special character (!@#$%^&*...)');
  }

  // Check for common weak patterns
  const weakPatterns = [
    /^(.)\1+$/, // All same character
    /password/i,
    /qwerty/i,
    /123456/,
    /admin/i,
  ];

  for (const pattern of weakPatterns) {
    if (pattern.test(password)) {
      errors.push('Password contains a common weak pattern');
      break;
    }
  }

  // Calculate strength
  let strength: PasswordValidationResult['strength'] = 'weak';
  if (errors.length === 0) {
    const lengthScore = Math.min(password.length / 20, 1);
    const varietyScore =
      [/[A-Z]/.test(password), /[a-z]/.test(password), /[0-9]/.test(password), /[!@#$%^&*]/.test(password)].filter(
        Boolean
      ).length / 4;

    const totalScore = (lengthScore + varietyScore) / 2;

    if (totalScore >= 0.8) strength = 'strong';
    else if (totalScore >= 0.6) strength = 'good';
    else if (totalScore >= 0.4) strength = 'fair';
  }

  return {
    valid: errors.length === 0,
    errors,
    strength,
  };
}

// Strong password schema for production use
export const strongPasswordSchema = z
  .string()
  .min(12, 'Password must be at least 12 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/, 'Password must contain at least one special character');

export const registerSchema = z.object({
  email: emailSchema,
  name: z.string().min(2, 'Name must be at least 2 characters'),
  phone: phoneSchema,
  password: strongPasswordSchema,
  role: z.enum(['CUSTOMER', 'VENDOR']).default('CUSTOMER'),
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
});

export const updateProfileSchema = z.object({
  name: z.string().min(2).optional(),
  phone: phoneSchema,
  avatar: z.string().url().optional(),
});

// Password reset request schema
export const passwordResetRequestSchema = z.object({
  email: emailSchema,
});

// Password reset with token schema
export const passwordResetSchema = z
  .object({
    token: z.string().min(1, 'Reset token is required'),
    password: strongPasswordSchema,
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

// Change password schema (for logged-in users)
export const changePasswordSchema = z
  .object({
    currentPassword: z.string().min(1, 'Current password is required'),
    newPassword: strongPasswordSchema,
    confirmPassword: z.string(),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: 'Passwords do not match',
    path: ['confirmPassword'],
  });

// ===========================================
// Vendor Schemas
// ===========================================

export const createVendorSchema = z.object({
  name: z.string().min(2, 'Vendor name must be at least 2 characters'),
  description: z.string().optional(),
  categories: z.array(z.string()).optional().default([]),
});

export const updateVendorSchema = z.object({
  name: z.string().min(2).optional(),
  description: z.string().optional(),
  image: z.string().url().optional(),
  isOpen: z.boolean().optional(),
  categories: z.array(z.string()).optional(),
});

// ===========================================
// Menu Item Schemas
// ===========================================

export const createMenuItemSchema = z.object({
  name: z.string().min(2, 'Menu item name must be at least 2 characters'),
  description: z.string().optional(),
  price: z.number().positive('Price must be positive'),
  category: z.string().min(1, 'Category is required'),
  preparationTime: z.number().int().positive().optional().default(10),
  isAvailable: z.boolean().optional().default(true),
});

export const updateMenuItemSchema = z.object({
  name: z.string().min(2).optional(),
  description: z.string().optional(),
  price: z.number().positive().optional(),
  image: z.string().url().optional(),
  category: z.string().optional(),
  preparationTime: z.number().int().positive().optional(),
  isAvailable: z.boolean().optional(),
});

// ===========================================
// Reservation Schemas
// ===========================================

export const reservationItemSchema = z.object({
  menuItemId: z.string().min(1),
  quantity: z.number().int().positive(),
});

export const createReservationSchema = z.object({
  vendorId: z.string().min(1, 'Vendor ID is required'),
  timeSlotId: z.string().min(1, 'Time slot is required'),
  customerName: z.string().min(2, 'Customer name is required'),
  customerContact: z.string().min(1, 'Contact is required'),
  paymentMethod: z.enum(['CASH', 'BANK_TRANSFER']),
  items: z.array(reservationItemSchema).min(1, 'At least one item is required'),
  notes: z.string().optional(),
});

export const updateReservationStatusSchema = z.object({
  status: z.enum([
    'PENDING',
    'CONFIRMED',
    'PREPARING',
    'READY',
    'COMPLETED',
    'CANCELLED',
  ]),
});

// ===========================================
// Time Slot Schemas
// ===========================================

export const createTimeSlotSchema = z.object({
  label: z.string().min(1),
  startTime: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Invalid time format (HH:mm)'),
  endTime: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, 'Invalid time format (HH:mm)'),
  period: z.enum(['MORNING', 'AFTERNOON']),
  maxOrders: z.number().int().positive().optional().default(50),
});

// ===========================================
// Review Schemas
// ===========================================

export const createReviewSchema = z.object({
  vendorId: z.string().min(1),
  rating: z.number().int().min(1).max(5),
  comment: z.string().optional(),
  images: z.array(z.string().url()).optional().default([]),
});

// ===========================================
// API Key Schemas
// ===========================================

export const createApiKeySchema = z.object({
  name: z.string().min(2, 'API key name must be at least 2 characters'),
  permissions: z.array(z.string()).optional().default(['read']),
  expiresAt: z.string().datetime().optional(),
});

// ===========================================
// Admin Schemas
// ===========================================

export const updateUserRoleSchema = z.object({
  role: z.enum(['CUSTOMER', 'VENDOR', 'ADMIN']),
});

export const createUserSchema = z.object({
  email: emailSchema,
  name: z.string().min(2),
  phone: phoneSchema,
  role: z.enum(['CUSTOMER', 'VENDOR', 'ADMIN']).default('CUSTOMER'),
});

// ===========================================
// Type Exports
// ===========================================

export type RegisterInput = z.infer<typeof registerSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
export type UpdateProfileInput = z.infer<typeof updateProfileSchema>;
export type PasswordResetRequestInput = z.infer<typeof passwordResetRequestSchema>;
export type PasswordResetInput = z.infer<typeof passwordResetSchema>;
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>;
export type CreateVendorInput = z.infer<typeof createVendorSchema>;
export type UpdateVendorInput = z.infer<typeof updateVendorSchema>;
export type CreateMenuItemInput = z.infer<typeof createMenuItemSchema>;
export type UpdateMenuItemInput = z.infer<typeof updateMenuItemSchema>;
export type CreateReservationInput = z.infer<typeof createReservationSchema>;
export type UpdateReservationStatusInput = z.infer<typeof updateReservationStatusSchema>;
export type CreateTimeSlotInput = z.infer<typeof createTimeSlotSchema>;
export type CreateReviewInput = z.infer<typeof createReviewSchema>;
export type CreateApiKeyInput = z.infer<typeof createApiKeySchema>;
export type PaginationInput = z.infer<typeof paginationSchema>;
