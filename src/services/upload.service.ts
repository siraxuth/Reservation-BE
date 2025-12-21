// Upload Service
import { prisma } from '../config/database';
import {
  uploadImage,
  uploadImageBuffer,
  deleteImage,
  type UploadFolder,
} from '../config/cloudinary';
import { NotFoundError, BadRequestError, ForbiddenError } from '../utils/errors';
import type { UploadType } from '@prisma/client';

export interface UploadResponse {
  id: string;
  userId: string;
  type: UploadType;
  url: string;
  publicId: string;
  format: string;
  width: number | null;
  height: number | null;
  bytes: number | null;
  originalName: string | null;
  createdAt: Date;
}

// Map upload type to Cloudinary folder
const typeToFolder: Record<UploadType, UploadFolder> = {
  AVATAR: 'avatars',
  VENDOR_IMAGE: 'vendors',
  MENU_IMAGE: 'menus',
  BANNER: 'banners',
  REVIEW_IMAGE: 'reviews',
};

/**
 * Upload file from base64 or URL
 */
export async function uploadFile(
  userId: string,
  type: UploadType,
  file: string,
  originalName?: string
): Promise<UploadResponse> {
  const folder = typeToFolder[type];

  const result = await uploadImage(file, folder);

  const upload = await prisma.upload.create({
    data: {
      userId,
      type,
      url: result.url,
      publicId: result.publicId,
      format: result.format,
      width: result.width,
      height: result.height,
      bytes: result.bytes,
      originalName,
    },
  });

  return upload;
}

/**
 * Upload file from buffer (multipart form)
 */
export async function uploadFileBuffer(
  userId: string,
  type: UploadType,
  buffer: Buffer,
  originalName?: string
): Promise<UploadResponse> {
  const folder = typeToFolder[type];

  const result = await uploadImageBuffer(buffer, folder, originalName);

  const upload = await prisma.upload.create({
    data: {
      userId,
      type,
      url: result.url,
      publicId: result.publicId,
      format: result.format,
      width: result.width,
      height: result.height,
      bytes: result.bytes,
      originalName,
    },
  });

  return upload;
}

/**
 * Delete upload
 */
export async function deleteUpload(
  uploadId: string,
  userId: string,
  isAdmin: boolean = false
): Promise<void> {
  const upload = await prisma.upload.findUnique({
    where: { id: uploadId },
  });

  if (!upload) {
    throw new NotFoundError('Upload');
  }

  if (upload.userId !== userId && !isAdmin) {
    throw new ForbiddenError('Not authorized to delete this upload');
  }

  // Delete from Cloudinary
  await deleteImage(upload.publicId);

  // Delete from database
  await prisma.upload.delete({ where: { id: uploadId } });
}

/**
 * Get uploads for a user
 */
export async function getUserUploads(
  userId: string,
  type?: UploadType
): Promise<UploadResponse[]> {
  const where: any = { userId };

  if (type) {
    where.type = type;
  }

  return prisma.upload.findMany({
    where,
    orderBy: { createdAt: 'desc' },
  });
}

/**
 * Get upload by ID
 */
export async function getUploadById(uploadId: string): Promise<UploadResponse> {
  const upload = await prisma.upload.findUnique({
    where: { id: uploadId },
  });

  if (!upload) {
    throw new NotFoundError('Upload');
  }

  return upload;
}

/**
 * Upload avatar and update user
 */
export async function uploadAvatar(
  userId: string,
  file: string
): Promise<UploadResponse> {
  const upload = await uploadFile(userId, 'AVATAR', file);

  // Update user avatar
  await prisma.user.update({
    where: { id: userId },
    data: { avatar: upload.url },
  });

  return upload;
}

/**
 * Upload vendor image and update vendor
 */
export async function uploadVendorImage(
  userId: string,
  vendorId: string,
  file: string
): Promise<UploadResponse> {
  const vendor = await prisma.vendor.findUnique({
    where: { id: vendorId },
  });

  if (!vendor) {
    throw new NotFoundError('Vendor');
  }

  if (vendor.userId !== userId) {
    throw new ForbiddenError('Not authorized to update this vendor');
  }

  const upload = await uploadFile(userId, 'VENDOR_IMAGE', file);

  // Update vendor image
  await prisma.vendor.update({
    where: { id: vendorId },
    data: { image: upload.url },
  });

  return upload;
}

/**
 * Upload menu item image and update menu item
 */
export async function uploadMenuItemImage(
  userId: string,
  menuItemId: string,
  file: string
): Promise<UploadResponse> {
  const menuItem = await prisma.menuItem.findUnique({
    where: { id: menuItemId },
    include: { vendor: true },
  });

  if (!menuItem) {
    throw new NotFoundError('Menu item');
  }

  if (menuItem.vendor.userId !== userId) {
    throw new ForbiddenError('Not authorized to update this menu item');
  }

  const upload = await uploadFile(userId, 'MENU_IMAGE', file);

  // Update menu item image
  await prisma.menuItem.update({
    where: { id: menuItemId },
    data: { image: upload.url },
  });

  return upload;
}

/**
 * Validate file type
 */
export function validateFileType(
  mimeType: string,
  allowedTypes: string[] = ['image/jpeg', 'image/png', 'image/webp', 'image/gif']
): boolean {
  return allowedTypes.includes(mimeType);
}

/**
 * Validate file size (default 5MB)
 */
export function validateFileSize(
  bytes: number,
  maxSizeBytes: number = 5 * 1024 * 1024
): boolean {
  return bytes <= maxSizeBytes;
}
