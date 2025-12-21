// Vercel Serverless Function Entry Point with Bun Runtime
import "dotenv/config";
import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import { openapi } from "@elysiajs/openapi";

// Import controllers
import {
  authController,
  passwordResetController,
} from "../src/controllers/auth.controller";
import { userController } from "../src/controllers/user.controller";
import { apiKeyController } from "../src/controllers/apikey.controller";
import { vendorController } from "../src/controllers/vendor.controller";
import {
  menuController,
  vendorMenuController,
} from "../src/controllers/menu.controller";
import {
  reservationController,
  vendorReservationsController,
} from "../src/controllers/reservation.controller";
import { timeSlotController } from "../src/controllers/timeslot.controller";
import { uploadController } from "../src/controllers/upload.controller";
import {
  reviewController,
  vendorReviewsController,
} from "../src/controllers/review.controller";
import {
  formatErrorResponse,
  getErrorStatusCode,
  AppError,
} from "../src/utils/errors";

const NODE_ENV = process.env.NODE_ENV || "production";
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
          : ["http://localhost:3000", "http://localhost:3002"],
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

// Export for Vercel Bun runtime
export default app;
