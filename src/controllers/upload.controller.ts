// Upload Controller
import { Elysia, t } from 'elysia';
import { bearer } from '@elysiajs/bearer';
import * as uploadService from '../services/upload.service';
import { validateSession, type AuthUser } from '../services/auth.service';
import { success } from '../utils/response';
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

export const uploadController = new Elysia({ prefix: '/uploads' })
  .use(bearer())

  // Upload image (base64 or URL)
  .post(
    '/',
    async ({ request, body }) => {
      const user = await getAuthUser(request);

      if (!body.file) {
        throw new BadRequestError('File is required');
      }

      const upload = await uploadService.uploadFile(
        user.id,
        body.type as any,
        body.file,
        body.originalName
      );

      return success(upload, 'File uploaded successfully');
    },
    {
      body: t.Object({
        type: t.Union([
          t.Literal('AVATAR'),
          t.Literal('VENDOR_IMAGE'),
          t.Literal('MENU_IMAGE'),
          t.Literal('BANNER'),
          t.Literal('REVIEW_IMAGE'),
        ]),
        file: t.String(), // base64 or URL
        originalName: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Uploads'],
        summary: 'Upload file',
        description: 'Upload file from base64 or URL',
      },
    }
  )

  // Upload avatar
  .post(
    '/avatar',
    async ({ request, body }) => {
      const user = await getAuthUser(request);

      if (!body.file) {
        throw new BadRequestError('File is required');
      }

      const upload = await uploadService.uploadAvatar(user.id, body.file);
      return success(upload, 'Avatar uploaded successfully');
    },
    {
      body: t.Object({
        file: t.String(),
      }),
      detail: {
        tags: ['Uploads'],
        summary: 'Upload avatar',
        description: 'Upload user avatar',
      },
    }
  )

  // Upload vendor image
  .post(
    '/vendor/:vendorId',
    async ({ request, params, body }) => {
      const user = await getAuthUser(request);

      if (!body.file) {
        throw new BadRequestError('File is required');
      }

      const upload = await uploadService.uploadVendorImage(
        user.id,
        params.vendorId,
        body.file
      );
      return success(upload, 'Vendor image uploaded successfully');
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      body: t.Object({
        file: t.String(),
      }),
      detail: {
        tags: ['Uploads'],
        summary: 'Upload vendor image',
        description: 'Upload vendor shop image',
      },
    }
  )

  // Upload menu item image
  .post(
    '/menu/:menuItemId',
    async ({ request, params, body }) => {
      const user = await getAuthUser(request);

      if (!body.file) {
        throw new BadRequestError('File is required');
      }

      const upload = await uploadService.uploadMenuItemImage(
        user.id,
        params.menuItemId,
        body.file
      );
      return success(upload, 'Menu item image uploaded successfully');
    },
    {
      params: t.Object({
        menuItemId: t.String(),
      }),
      body: t.Object({
        file: t.String(),
      }),
      detail: {
        tags: ['Uploads'],
        summary: 'Upload menu image',
        description: 'Upload menu item image',
      },
    }
  )

  // Get my uploads
  .get(
    '/me',
    async ({ request, query }) => {
      const user = await getAuthUser(request);

      const uploads = await uploadService.getUserUploads(
        user.id,
        query.type as any
      );
      return success(uploads);
    },
    {
      query: t.Object({
        type: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Uploads'],
        summary: 'Get my uploads',
        description: 'Get current user uploads',
      },
    }
  )

  // Get upload by ID
  .get(
    '/:uploadId',
    async ({ params }) => {
      const upload = await uploadService.getUploadById(params.uploadId);
      return success(upload);
    },
    {
      params: t.Object({
        uploadId: t.String(),
      }),
      detail: {
        tags: ['Uploads'],
        summary: 'Get upload',
        description: 'Get upload details',
      },
    }
  )

  // Delete upload
  .delete(
    '/:uploadId',
    async ({ request, params }) => {
      const user = await getAuthUser(request);

      await uploadService.deleteUpload(
        params.uploadId,
        user.id,
        user.role === 'ADMIN'
      );
      return success(null, 'Upload deleted');
    },
    {
      params: t.Object({
        uploadId: t.String(),
      }),
      detail: {
        tags: ['Uploads'],
        summary: 'Delete upload',
        description: 'Delete an upload',
      },
    }
  );
