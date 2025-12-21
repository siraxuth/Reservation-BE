// Entry Point - Full API with Elysia + Bun.serve
import "dotenv/config";
import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import { openapi } from "@elysiajs/openapi";
import logixlysia from "logixlysia";
// Import controllers
import {
  authController,
  passwordResetController,
} from "./controllers/auth.controller";
import { userController } from "./controllers/user.controller";
import { apiKeyController } from "./controllers/apikey.controller";
import { vendorController } from "./controllers/vendor.controller";
import {
  menuController,
  vendorMenuController,
} from "./controllers/menu.controller";
import {
  reservationController,
  vendorReservationsController,
} from "./controllers/reservation.controller";
import { timeSlotController } from "./controllers/timeslot.controller";
import { uploadController } from "./controllers/upload.controller";
import {
  reviewController,
  vendorReviewsController,
} from "./controllers/review.controller";
import {
  formatErrorResponse,
  getErrorStatusCode,
  AppError,
} from "./utils/errors";

const PORT = Number(process.env.PORT) || 3002;
const NODE_ENV = process.env.NODE_ENV || "development";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";

// Create Elysia app
const app = new Elysia()
  // Global error handler
  .onError(({ code, error, set }) => {
    console.error(`[Error] ${code}:`, error);

    // Handle known errors
    if (error instanceof AppError) {
      set.status = error.statusCode;
      return formatErrorResponse(error);
    }

    // Handle validation errors
    if (code === "VALIDATION") {
      set.status = 400;
      return {
        success: false,
        error: "Validation failed",
        code: "VALIDATION_ERROR",
        details: error.message,
      };
    }

    // Handle not found
    if (code === "NOT_FOUND") {
      set.status = 404;
      return {
        success: false,
        error: "Route not found",
        code: "NOT_FOUND",
      };
    }

    // Default error response
    set.status = getErrorStatusCode(error);
    return formatErrorResponse(error);
  })
  // CORS
  .use(
    cors({
      origin:
        NODE_ENV === "production"
          ? FRONTEND_URL
          : ["http://localhost:3000", `http://localhost:${PORT}`],
      credentials: true,
      allowedHeaders: [
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Requested-With",
      ],
      methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    })
  )

  // logging
  .use(
    logixlysia({
      config: {
        showStartupMessage: true,
        startupMessageFormat: "banner",
        timestamp: {
          translateTime: "yyyy-mm-dd HH:MM:ss",
        },
        ip: true,
        customLogFormat:
          "🦊 {now} {level} {duration} {method} {pathname} {status}",
      },
    })
  )

  // Openapi documentation
  .use(openapi({ path: "/docs" }))

  // Health check
  .get("/health", () => ({
    success: true,
    data: {
      status: "healthy",
      timestamp: new Date().toISOString(),
      version: "1.0.0",
    },
  }))

  // API Routes
  .group("/api", (app) =>
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
      .use(reviewController)
      .use(vendorReviewsController)
  )

  // 404 handler
  .all(
    "*",
    ({ set }) => {
      set.status = 404;
      return {
        success: false,
        error: "Endpoint not found",
        code: "NOT_FOUND",
      };
    },
    {
      detail: {
        hide: true,
      },
    }
  );

// Use Bun.serve with Elysia's fetch handler
// const server = Bun.serve({
//   port: PORT,
//   fetch: app.fetch,
// });

// app.listen({
//   port: PORT,
// });

// console.log(`
// ╔════════════════════════════════════════════════════════════╗
// ║                                                            ║
// ║   🍔 Food Queue Reservation API                            ║
// ║                                                            ║
// ║   Server running on: http://localhost:${PORT}                 ║
// ║   Swagger docs:      http://localhost:${PORT}/docs            ║
// ║   Environment:       ${NODE_ENV.padEnd(30)}        ║
// ║                                                            ║
// ╚════════════════════════════════════════════════════════════╝
// `);
