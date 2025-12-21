// Cloudinary Configuration
// Image upload and management

import { v2 as cloudinary, UploadApiOptions, UploadApiResponse } from 'cloudinary';
import { env } from './env';

// Configure Cloudinary
cloudinary.config({
  cloud_name: env.CLOUDINARY_CLOUD_NAME,
  api_key: env.CLOUDINARY_API_KEY,
  api_secret: env.CLOUDINARY_API_SECRET,
  secure: true,
});

export type UploadFolder = 'avatars' | 'vendors' | 'menus' | 'banners' | 'reviews';

export interface UploadResult {
  url: string;
  publicId: string;
  format: string;
  width: number;
  height: number;
  bytes: number;
}

// Upload options per folder
const folderOptions: Record<UploadFolder, UploadApiOptions> = {
  avatars: {
    folder: 'reservation/avatars',
    transformation: [
      { width: 200, height: 200, crop: 'fill', gravity: 'face' },
      { quality: 'auto:good' },
      { format: 'auto' },
    ],
  },
  vendors: {
    folder: 'reservation/vendors',
    transformation: [
      { width: 800, height: 600, crop: 'fill' },
      { quality: 'auto:good' },
      { format: 'auto' },
    ],
  },
  menus: {
    folder: 'reservation/menus',
    transformation: [
      { width: 400, height: 400, crop: 'fill' },
      { quality: 'auto:good' },
      { format: 'auto' },
    ],
  },
  banners: {
    folder: 'reservation/banners',
    transformation: [
      { width: 1920, height: 600, crop: 'fill' },
      { quality: 'auto:good' },
      { format: 'auto' },
    ],
  },
  reviews: {
    folder: 'reservation/reviews',
    transformation: [
      { width: 800, height: 800, crop: 'limit' },
      { quality: 'auto:good' },
      { format: 'auto' },
    ],
  },
};

/**
 * Upload image from base64 or URL
 */
export async function uploadImage(
  file: string, // base64 or URL
  folder: UploadFolder,
  publicId?: string
): Promise<UploadResult> {
  const options: UploadApiOptions = {
    ...folderOptions[folder],
    resource_type: 'image',
    unique_filename: true,
    overwrite: true,
  };

  if (publicId) {
    options.public_id = publicId;
  }

  const result: UploadApiResponse = await cloudinary.uploader.upload(file, options);

  return {
    url: result.secure_url,
    publicId: result.public_id,
    format: result.format,
    width: result.width,
    height: result.height,
    bytes: result.bytes,
  };
}

/**
 * Upload image from buffer (file upload)
 */
export async function uploadImageBuffer(
  buffer: Buffer,
  folder: UploadFolder,
  originalName?: string
): Promise<UploadResult> {
  return new Promise((resolve, reject) => {
    const options: UploadApiOptions = {
      ...folderOptions[folder],
      resource_type: 'image',
      unique_filename: true,
    };

    const uploadStream = cloudinary.uploader.upload_stream(
      options,
      (error, result) => {
        if (error) {
          reject(error);
        } else if (result) {
          resolve({
            url: result.secure_url,
            publicId: result.public_id,
            format: result.format,
            width: result.width,
            height: result.height,
            bytes: result.bytes,
          });
        }
      }
    );

    uploadStream.end(buffer);
  });
}

/**
 * Delete image by public ID
 */
export async function deleteImage(publicId: string): Promise<boolean> {
  try {
    const result = await cloudinary.uploader.destroy(publicId);
    return result.result === 'ok';
  } catch {
    return false;
  }
}

/**
 * Get optimized URL for an image
 */
export function getOptimizedUrl(
  publicId: string,
  options?: {
    width?: number;
    height?: number;
    crop?: string;
  }
): string {
  return cloudinary.url(publicId, {
    secure: true,
    quality: 'auto',
    format: 'auto',
    ...options,
  });
}

export { cloudinary };
