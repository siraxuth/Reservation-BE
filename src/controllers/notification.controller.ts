// Notification Controller - Polling-based notifications + optional FCM
import { Elysia, t } from "elysia";
import { bearer } from "@elysiajs/bearer";
import { validateSession, type AuthUser } from "../services/auth.service";
import { UnauthorizedError } from "../utils/errors";
import { success } from "../utils/response";
import {
  getUnreadNotifications,
  getNotifications,
  markAsRead,
  markAllAsRead,
  getUnreadCount,
} from "../services/notification.service";

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

export const notificationController = new Elysia({ prefix: "/notifications" })
  .use(bearer())

  // Poll for unread notifications (frontend calls this every 5s)
  .get(
    "/unread",
    async ({ request }) => {
      const user = await getAuthUser(request);
      const notifications = await getUnreadNotifications(user.id);
      const count = notifications.length;

      return success({ notifications, count });
    },
    {
      detail: {
        tags: ["Notifications"],
        summary: "Get unread notifications",
        description:
          "Poll for unread notifications. Frontend should call this every 5 seconds.",
      },
    },
  )

  // Get all notifications (with pagination)
  .get(
    "/all",
    async ({ request, query }) => {
      const user = await getAuthUser(request);
      const limit = query.limit ? parseInt(query.limit as string) : 20;
      const cursor = query.cursor as string | undefined;
      const notifications = await getNotifications(user.id, limit, cursor);

      return success({ notifications });
    },
    {
      query: t.Object({
        limit: t.Optional(t.String()),
        cursor: t.Optional(t.String()),
      }),
      detail: {
        tags: ["Notifications"],
        summary: "Get all notifications",
        description:
          "Get all notifications for the authenticated user, paginated.",
      },
    },
  )

  // Get unread count only (lightweight endpoint)
  .get(
    "/count",
    async ({ request }) => {
      const user = await getAuthUser(request);
      const count = await getUnreadCount(user.id);

      return success({ count });
    },
    {
      detail: {
        tags: ["Notifications"],
        summary: "Get unread notification count",
        description: "Get the count of unread notifications.",
      },
    },
  )

  // Mark a single notification as read
  .patch(
    "/:id/read",
    async ({ request, params }) => {
      const user = await getAuthUser(request);
      await markAsRead(params.id, user.id);

      return success(null, "Notification marked as read");
    },
    {
      params: t.Object({
        id: t.String(),
      }),
      detail: {
        tags: ["Notifications"],
        summary: "Mark notification as read",
      },
    },
  )

  // Mark all notifications as read
  .patch(
    "/read-all",
    async ({ request }) => {
      const user = await getAuthUser(request);
      await markAllAsRead(user.id);

      return success(null, "All notifications marked as read");
    },
    {
      detail: {
        tags: ["Notifications"],
        summary: "Mark all notifications as read",
      },
    },
  );
