// Reservation Controller
import { Elysia, t } from "elysia";
import { bearer } from "@elysiajs/bearer";
import * as reservationService from "../services/reservation.service";
import { validateSession, type AuthUser } from "../services/auth.service";
import {
  requireAuth,
  requireVendorOrAdmin,
  requireAdmin,
} from "../middlewares/auth.middleware";
import { success, paginated } from "../utils/response";
import {
  createReservationSchema,
  updateReservationStatusSchema,
  paginationSchema,
} from "../utils/validation";
import { BadRequestError, UnauthorizedError } from "../utils/errors";

// Helper function to extract and validate auth
async function getAuthUser(request: Request): Promise<AuthUser> {
  const authHeader = request.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    throw new UnauthorizedError("Authentication required");
  }

  const token = authHeader.slice(7);
  const user = await validateSession(token);

  if (!user) {
    throw new UnauthorizedError("Invalid or expired session");
  }

  return user;
}

export const reservationController = new Elysia({ prefix: "/reservations" })
  .use(bearer())

  // Create reservation
  .post(
    "/",
    async ({ request, body }) => {
      const user = await getAuthUser(request);

      const validated = createReservationSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const reservation = await reservationService.createReservation(
        user.id,
        validated.data,
      );
      return success(reservation, "Reservation created successfully");
    },
    {
      body: t.Object({
        vendorId: t.String(),
        timeSlotId: t.String(),
        customerName: t.String(),
        customerContact: t.String(),
        paymentMethod: t.Union([t.Literal("CASH"), t.Literal("BANK_TRANSFER")]),
        items: t.Array(
          t.Object({
            menuItemId: t.String(),
            quantity: t.Number(),
          }),
        ),
        notes: t.Optional(t.String()),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "Create reservation",
        description: "Create a new food reservation",
      },
    },
  )

  // Get my reservations
  .get(
    "/me",
    async ({ request, query }) => {
      const user = await getAuthUser(request);

      const pagination = paginationSchema.safeParse(query);
      const paginationData = pagination.success
        ? pagination.data
        : { page: 1, limit: 20 };
      const result = await reservationService.getCustomerReservations(
        user.id,
        paginationData,
        {
          status: query.status as any,
        },
      );
      return paginated(result);
    },
    {
      query: t.Object({
        page: t.Optional(t.String()),
        limit: t.Optional(t.String()),
        status: t.Optional(t.String()),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "Get my reservations",
        description: "Get current user reservations",
      },
    },
  )

  // Get my queue status (active reservations with position info)
  .get(
    "/me/queue-status",
    async ({ request }) => {
      const user = await getAuthUser(request);
      const result = await reservationService.getQueueStatus(user.id);
      return success(result);
    },
    {
      detail: {
        tags: ["Reservations"],
        summary: "Get queue status",
        description:
          "Get active queue status with position info for current user",
      },
    },
  )

  // Get reservation by ID
  .get(
    "/:reservationId",
    async ({ request, params }) => {
      const user = await getAuthUser(request);
      const reservation = await reservationService.getReservationById(
        params.reservationId,
        user.id,
        user.role,
      );
      return success(reservation);
    },
    {
      params: t.Object({
        reservationId: t.String(),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "Get reservation",
        description: "Get reservation details",
      },
    },
  )

  // Cancel reservation
  .post(
    "/:reservationId/cancel",
    async ({ request, params }) => {
      const user = await getAuthUser(request);
      const reservation = await reservationService.cancelReservation(
        params.reservationId,
        user.id,
        user.role,
      );
      return success(reservation, "Reservation cancelled");
    },
    {
      params: t.Object({
        reservationId: t.String(),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "Cancel reservation",
        description: "Cancel a reservation",
      },
    },
  )

  // Vendor/Admin routes
  .use(requireVendorOrAdmin)

  // Update reservation status
  .patch(
    "/:reservationId/status",
    async ({ request, params, body }) => {
      const user = await getAuthUser(request);
      const validated = updateReservationStatusSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const reservation = await reservationService.updateReservationStatus(
        params.reservationId,
        user.id,
        user.role,
        validated.data.status,
      );
      return success(reservation, `Status updated to ${validated.data.status}`);
    },
    {
      params: t.Object({
        reservationId: t.String(),
      }),
      body: t.Object({
        status: t.Union([
          t.Literal("PENDING"),
          t.Literal("CONFIRMED"),
          t.Literal("PREPARING"),
          t.Literal("READY"),
          t.Literal("COMPLETED"),
          t.Literal("CANCELLED"),
        ]),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "Update status",
        description: "Update reservation status",
      },
    },
  )

  // Resend "ready" email to customer
  .post(
    "/:reservationId/notify",
    async ({ request, params }) => {
      const user = await getAuthUser(request);
      const result = await reservationService.notifyCustomer(
        params.reservationId,
        user.id,
        user.role,
      );
      return success(result, "ส่งการแจ้งเตือนถึงลูกค้าแล้ว");
    },
    {
      params: t.Object({
        reservationId: t.String(),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "Notify customer",
        description: "Resend ready email notification to customer",
      },
    },
  )

  // Admin routes
  .use(requireAdmin)

  // Get all reservations (admin)
  .get(
    "/",
    async ({ query }) => {
      const pagination = paginationSchema.safeParse(query);
      const paginationData = pagination.success
        ? pagination.data
        : { page: 1, limit: 20 };
      const result = await reservationService.getAllReservations(
        paginationData,
        {
          status: query.status as any,
          vendorId: query.vendorId,
          date: query.date,
        },
      );
      return paginated(result);
    },
    {
      query: t.Object({
        page: t.Optional(t.String()),
        limit: t.Optional(t.String()),
        status: t.Optional(t.String()),
        vendorId: t.Optional(t.String()),
        date: t.Optional(t.String()),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "List all reservations",
        description: "Get all reservations (admin only)",
      },
    },
  )

  // Get reservation stats (admin)
  .get(
    "/stats/overview",
    async ({ query }) => {
      const stats = await reservationService.getReservationStats(
        query.vendorId,
      );
      return success(stats);
    },
    {
      query: t.Object({
        vendorId: t.Optional(t.String()),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "Get statistics",
        description: "Get reservation statistics",
      },
    },
  );

// Vendor Reservations Routes
export const vendorReservationsController = new Elysia({
  prefix: "/vendors/:vendorId/reservations",
})
  .use(requireAuth)
  .use(requireVendorOrAdmin)

  // Get vendor's reservations
  .get(
    "/",
    async ({ request, params, query }) => {
      const user = await getAuthUser(request);
      const pagination = paginationSchema.safeParse(query);
      const paginationData = pagination.success
        ? pagination.data
        : { page: 1, limit: 20 };
      const result = await reservationService.getVendorReservations(
        params.vendorId,
        user.id,
        user.role,
        paginationData,
        {
          status: query.status as any,
          date: query.date,
        },
      );
      return paginated(result);
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      query: t.Object({
        page: t.Optional(t.String()),
        limit: t.Optional(t.String()),
        status: t.Optional(t.String()),
        date: t.Optional(t.String()),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "Get vendor reservations",
        description: "Get reservations for a vendor",
      },
    },
  )

  // Get vendor reservation stats
  .get(
    "/stats",
    async ({ params }) => {
      const stats = await reservationService.getReservationStats(
        params.vendorId,
      );
      return success(stats);
    },
    {
      params: t.Object({
        vendorId: t.String(),
      }),
      detail: {
        tags: ["Reservations"],
        summary: "Get vendor stats",
        description: "Get reservation statistics for a vendor",
      },
    },
  );
