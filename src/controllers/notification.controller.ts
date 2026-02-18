// Notification Controller - Push notification token management
import { Elysia, t } from 'elysia';
import { bearer } from '@elysiajs/bearer';
import { validateSession, type AuthUser } from '../services/auth.service';
import { UnauthorizedError } from '../utils/errors';
import { success } from '../utils/response';
import {
  registerToken,
  unregisterToken,
  isFCMConfigured,
} from '../services/push.service';

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

export const notificationController = new Elysia({ prefix: '/notifications' })
  .use(bearer())

  // Check if push notifications are available
  .get(
    '/status',
    async () => {
      return success({
        pushEnabled: isFCMConfigured(),
      });
    },
    {
      detail: {
        tags: ['Notifications'],
        summary: 'Get notification status',
        description: 'Check if push notifications are configured and available',
      },
    }
  )

  // Register FCM token
  .post(
    '/register',
    async ({ request, body }) => {
      const user = await getAuthUser(request);

      await registerToken(
        user.id,
        body.token,
        body.device,
        request.headers.get('user-agent') || undefined
      );

      return success(null, 'Push notification token registered');
    },
    {
      body: t.Object({
        token: t.String({ minLength: 1 }),
        device: t.Optional(
          t.Union([
            t.Literal('web'),
            t.Literal('android'),
            t.Literal('ios'),
          ])
        ),
      }),
      detail: {
        tags: ['Notifications'],
        summary: 'Register push token',
        description: 'Register a Firebase Cloud Messaging token for push notifications',
      },
    }
  )

  // Unregister FCM token
  .post(
    '/unregister',
    async ({ request, body }) => {
      await getAuthUser(request);

      await unregisterToken(body.token);

      return success(null, 'Push notification token unregistered');
    },
    {
      body: t.Object({
        token: t.String({ minLength: 1 }),
      }),
      detail: {
        tags: ['Notifications'],
        summary: 'Unregister push token',
        description: 'Unregister a Firebase Cloud Messaging token',
      },
    }
  );
