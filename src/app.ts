// Main Application
import { Elysia } from 'elysia';
import { cors } from '@elysiajs/cors';
import { swagger } from '@elysiajs/swagger';
import { env } from './config/env';

// Controllers
import { authController, passwordResetController } from './controllers/auth.controller';
import { userController } from './controllers/user.controller';
import { apiKeyController } from './controllers/apikey.controller';
import { vendorController } from './controllers/vendor.controller';
import { menuController, vendorMenuController } from './controllers/menu.controller';
import { reservationController, vendorReservationsController } from './controllers/reservation.controller';
import { timeSlotController } from './controllers/timeslot.controller';
import { uploadController } from './controllers/upload.controller';

// Create Elysia app
export const app = new Elysia({ name: 'app' })

  // CORS configuration
  .use(
    cors({
      origin: env.IS_PRODUCTION
        ? env.FRONTEND_URL
        : ['http://localhost:3000', 'http://localhost:3001'],
      credentials: true,
      allowedHeaders: [
        'Content-Type',
        'Authorization',
        'X-API-Key',
        'X-Requested-With',
      ],
      methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    })
  )

  // Swagger documentation
  .use(swagger({ path: '/docs' }))

  // Health check
  .get('/health', () => ({
    success: true,
    data: {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
    },
  }))

  // API Routes
  .group('/api', (app) =>
    app
      .use(authController)
      .use(passwordResetController)
      .use(userController)
      .use(apiKeyController)
      .use(vendorController)
      .use(menuController)
      .use(vendorMenuController)
      .use(reservationController)
      .use(vendorReservationsController)
      .use(timeSlotController)
      .use(uploadController)
  )

  // 404 handler
  .all('*', ({ set }) => {
    set.status = 404;
    return {
      success: false,
      error: 'Endpoint not found',
      code: 'NOT_FOUND',
    };
  });

export type App = typeof app;
