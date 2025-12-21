// Authentication Controller
import { Elysia, t } from 'elysia';
import { Google } from 'arctic';
import * as authService from '../services/auth.service';
import { env } from '../config/env';
import { authPlugin, requireAuth, type AuthUser } from '../middlewares/auth.middleware';
import { success } from '../utils/response';
import {
  registerSchema,
  loginSchema,
  passwordResetRequestSchema,
  passwordResetSchema,
  changePasswordSchema,
  strongPasswordSchema,
} from '../utils/validation';
import { BadRequestError } from '../utils/errors';

// Type helpers
type AuthCtx = { user: AuthUser };
type OptionalAuthCtx = { user: AuthUser | undefined };

// Google OAuth client
const google = new Google(
  env.GOOGLE_CLIENT_ID,
  env.GOOGLE_CLIENT_SECRET,
  env.GOOGLE_CALLBACK_URL
);

// In-memory store for OAuth state and code verifiers (use Redis in production)
const oauthStore = new Map<string, { codeVerifier: string; expiresAt: number }>();

// Cleanup expired entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of oauthStore.entries()) {
    if (value.expiresAt < now) {
      oauthStore.delete(key);
    }
  }
}, 60000);

export const authController = new Elysia({ prefix: '/auth' })
  // Health check
  .get('/health', () => success({ status: 'ok' }))

  // Register with email/password
  .post(
    '/register',
    async ({ body }) => {
      const validated = registerSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const session = await authService.register(validated.data);
      return success(
        {
          user: session.user,
          token: session.token,
          expiresAt: session.expiresAt,
        },
        'Registration successful'
      );
    },
    {
      body: t.Object({
        email: t.String(),
        name: t.String(),
        phone: t.Optional(t.String()),
        password: t.String(),
        role: t.Optional(t.Union([t.Literal('CUSTOMER'), t.Literal('VENDOR')])),
      }),
      detail: {
        tags: ['Auth'],
        summary: 'Register new user',
        description: 'Register a new user with email and password',
      },
    }
  )

  // Login with email/password
  .post(
    '/login',
    async ({ body }) => {
      const validated = loginSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const session = await authService.login(validated.data);
      return success(
        {
          user: session.user,
          token: session.token,
          expiresAt: session.expiresAt,
        },
        'Login successful'
      );
    },
    {
      body: t.Object({
        email: t.String(),
        password: t.String(),
      }),
      detail: {
        tags: ['Auth'],
        summary: 'Login',
        description: 'Login with email and password',
      },
    }
  )

  // Google OAuth - Start
  .get(
    '/google',
    async ({ redirect }) => {
      const state = crypto.randomUUID();
      const codeVerifier = crypto.randomUUID() + crypto.randomUUID(); // Longer verifier for security
      const scopes = ['openid', 'profile', 'email'];
      const url = await google.createAuthorizationURL(state, codeVerifier, { scopes });

      // Store the code verifier with state (expires in 10 minutes)
      oauthStore.set(state, {
        codeVerifier,
        expiresAt: Date.now() + 10 * 60 * 1000,
      });

      // Add access_type=offline for refresh token
      url.searchParams.set('access_type', 'offline');
      url.searchParams.set('prompt', 'consent');

      return redirect(url.toString());
    },
    {
      detail: {
        tags: ['Auth'],
        summary: 'Google OAuth',
        description: 'Start Google OAuth flow',
      },
    }
  )

  // Google OAuth - Callback
  .get(
    '/google/callback',
    async ({ query, redirect }) => {
      const { code, state, error } = query;

      if (error || !code) {
        return redirect(`${env.FRONTEND_URL}/login?error=oauth_failed`);
      }

      try {
        // Get the stored code verifier using the state
        const storedData = state ? oauthStore.get(state) : null;
        if (!storedData) {
          console.error('OAuth state not found or expired');
          return redirect(`${env.FRONTEND_URL}/login?error=oauth_expired`);
        }

        // Delete the stored data (one-time use)
        oauthStore.delete(state!);

        // Exchange code for tokens with the stored code verifier
        const tokens = await google.validateAuthorizationCode(code, storedData.codeVerifier);

        // Get user info from Google
        const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
          headers: {
            Authorization: `Bearer ${tokens.accessToken}`,
          },
        });

        if (!response.ok) {
          throw new Error('Failed to fetch user info');
        }

        const googleUser = (await response.json()) as {
          sub: string;
          email: string;
          name: string;
          picture?: string;
        };

        // Login or register with Google
        const session = await authService.googleAuth(
          {
            id: googleUser.sub,
            email: googleUser.email,
            name: googleUser.name,
            picture: googleUser.picture,
          },
          {
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken ?? undefined,
            expiresAt: tokens.accessTokenExpiresAt
              ? Math.floor(tokens.accessTokenExpiresAt.getTime() / 1000)
              : undefined,
          }
        );

        console.log('Google OAuth session created:', {
          userId: session.user.id,
          email: session.user.email,
          tokenPrefix: session.token.substring(0, 10) + '...',
          expiresAt: session.expiresAt,
        });

        // Redirect to frontend with token
        const redirectUrl = new URL(`${env.FRONTEND_URL}/auth/callback`);
        redirectUrl.searchParams.set('token', session.token);
        redirectUrl.searchParams.set('expires', session.expiresAt.toISOString());

        return redirect(redirectUrl.toString());
      } catch (err) {
        console.error('Google OAuth error:', err);
        return redirect(`${env.FRONTEND_URL}/login?error=oauth_failed`);
      }
    },
    {
      query: t.Object({
        code: t.Optional(t.String()),
        state: t.Optional(t.String()),
        error: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Auth'],
        summary: 'Google OAuth Callback',
        description: 'Handle Google OAuth callback',
      },
    }
  )

  // Get current user
  .use(authPlugin)
  .get(
    '/me',
    async (ctx) => {
      let { user, bearer } = ctx as unknown as OptionalAuthCtx & { bearer?: string };
      console.log('/auth/me called:', {
        hasBearer: !!bearer,
        bearerPrefix: bearer ? bearer.substring(0, 10) + '...' : null,
        hasUser: !!user,
        userId: user?.id,
      });

      // If authPlugin didn't set user but we have bearer, try validating directly
      if (!user && bearer) {
        console.log('Attempting direct session validation...');
        const validatedUser = await authService.validateSession(bearer);
        console.log('Direct validation result:', { hasUser: !!validatedUser });
        if (validatedUser) {
          return success(validatedUser);
        }
      }

      if (!user) {
        // Return debug info for troubleshooting
        return {
          success: true,
          data: null,
          message: 'Not authenticated',
          debug: {
            hasBearer: !!bearer,
            bearerPrefix: bearer ? bearer.substring(0, 10) + '...' : null,
          },
        };
      }
      return success(user);
    },
    {
      detail: {
        tags: ['Auth'],
        summary: 'Get current user',
        description: 'Get currently authenticated user',
      },
    }
  )

  // Logout
  .use(requireAuth)
  .post(
    '/logout',
    async (ctx) => {
      const { bearer } = ctx as unknown as { bearer: string };
      if (bearer) {
        await authService.logout(bearer);
      }
      return success(null, 'Logged out successfully');
    },
    {
      detail: {
        tags: ['Auth'],
        summary: 'Logout',
        description: 'Logout current session',
      },
    }
  )

  // Logout all sessions
  .post(
    '/logout-all',
    async (ctx) => {
      const { user } = ctx as unknown as AuthCtx;
      await authService.logoutAll(user.id);
      return success(null, 'All sessions logged out');
    },
    {
      detail: {
        tags: ['Auth'],
        summary: 'Logout all',
        description: 'Logout all sessions for current user',
      },
    }
  )

  // Get user sessions
  .get(
    '/sessions',
    async (ctx) => {
      const { user } = ctx as unknown as AuthCtx;
      const sessions = await authService.getUserSessions(user.id);
      return success(sessions);
    },
    {
      detail: {
        tags: ['Auth'],
        summary: 'Get sessions',
        description: 'Get all active sessions for current user',
      },
    }
  )

  // Delete specific session
  .delete(
    '/sessions/:sessionId',
    async (ctx) => {
      const { user, params } = ctx as unknown as AuthCtx & { params: { sessionId: string } };
      await authService.deleteSession(user.id, params.sessionId);
      return success(null, 'Session deleted');
    },
    {
      params: t.Object({
        sessionId: t.String(),
      }),
      detail: {
        tags: ['Auth'],
        summary: 'Delete session',
        description: 'Delete a specific session',
      },
    }
  )

  // Change password (requires auth)
  .post(
    '/change-password',
    async ({ body, ...ctx }) => {
      const { user } = ctx as unknown as AuthCtx;
      const validated = changePasswordSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      await authService.changePassword(user.id, validated.data.currentPassword, validated.data.newPassword);
      return success(null, 'Password changed successfully');
    },
    {
      body: t.Object({
        currentPassword: t.String(),
        newPassword: t.String(),
        confirmPassword: t.String(),
      }),
      detail: {
        tags: ['Auth'],
        summary: 'Change password',
        description: 'Change password for authenticated user',
      },
    }
  )

  // Resend verification email (requires auth)
  .post(
    '/resend-verification',
    async (ctx) => {
      const { user } = ctx as unknown as AuthCtx;
      await authService.resendVerificationEmail(user.id);
      return success(null, 'Verification email sent');
    },
    {
      detail: {
        tags: ['Auth'],
        summary: 'Resend verification email',
        description: 'Resend email verification link',
      },
    }
  );

// Public password reset routes (no auth required)
export const passwordResetController = new Elysia({ prefix: '/auth' })
  // Request password reset
  .post(
    '/forgot-password',
    async ({ body }) => {
      const validated = passwordResetRequestSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      await authService.requestPasswordReset(validated.data.email);
      // Always return success to prevent email enumeration
      return success(null, 'If an account exists with this email, a password reset link has been sent.');
    },
    {
      body: t.Object({
        email: t.String(),
      }),
      detail: {
        tags: ['Auth'],
        summary: 'Request password reset',
        description: 'Request a password reset email',
      },
    }
  )

  // Reset password with token
  .post(
    '/reset-password',
    async ({ body }) => {
      const validated = passwordResetSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      // Validate password strength
      const passwordValidation = strongPasswordSchema.safeParse(validated.data.password);
      if (!passwordValidation.success) {
        throw new BadRequestError(passwordValidation.error.errors[0].message);
      }

      await authService.resetPassword(validated.data.token, validated.data.password);
      return success(null, 'Password has been reset successfully. Please login with your new password.');
    },
    {
      body: t.Object({
        token: t.String(),
        password: t.String(),
        confirmPassword: t.String(),
      }),
      detail: {
        tags: ['Auth'],
        summary: 'Reset password',
        description: 'Reset password using reset token',
      },
    }
  )

  // Verify email with token
  .post(
    '/verify-email',
    async ({ body }) => {
      await authService.verifyEmail(body.token);
      return success(null, 'Email verified successfully');
    },
    {
      body: t.Object({
        token: t.String(),
      }),
      detail: {
        tags: ['Auth'],
        summary: 'Verify email',
        description: 'Verify email address with token',
      },
    }
  )

  // Test email (for development/testing)
  .post(
    '/test-email',
    async ({ body }) => {
      const { sendTestEmail } = await import('../services/email.service');
      const result = await sendTestEmail(body.email);
      return result.success ? success(result, result.message) : { success: false, error: result.message };
    },
    {
      body: t.Object({
        email: t.String(),
      }),
      detail: {
        tags: ['Auth'],
        summary: 'Test email',
        description: 'Send a test email to verify SMTP configuration',
      },
    }
  );
