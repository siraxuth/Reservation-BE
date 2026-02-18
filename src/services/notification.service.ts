// Notification Service - Polling-based notifications (no Firebase needed)
import { prisma } from "../config/database";

// Status label mapping (Thai)
const STATUS_LABELS: Record<string, string> = {
  PENDING: "รอยืนยัน",
  CONFIRMED: "ยืนยันแล้ว",
  PREPARING: "กำลังเตรียมอาหาร",
  READY: "พร้อมรับอาหาร",
  COMPLETED: "เสร็จสิ้น",
  CANCELLED: "ยกเลิกแล้ว",
};

const STATUS_EMOJI: Record<string, string> = {
  PENDING: "⏳",
  CONFIRMED: "✅",
  PREPARING: "👨‍🍳",
  READY: "🔔",
  COMPLETED: "🎉",
  CANCELLED: "❌",
};

/**
 * Create a notification for a user
 */
export async function createNotification(params: {
  userId: string;
  title: string;
  body: string;
  type: string;
  data?: Record<string, unknown>;
}) {
  return prisma.notification.create({
    data: {
      userId: params.userId,
      title: params.title,
      body: params.body,
      type: params.type,
      data: params.data || {},
    },
  });
}

/**
 * Get unread notifications for a user
 */
export async function getUnreadNotifications(userId: string) {
  return prisma.notification.findMany({
    where: {
      userId,
      isRead: false,
    },
    orderBy: { createdAt: "desc" },
    take: 50,
  });
}

/**
 * Get all notifications for a user (paginated)
 */
export async function getNotifications(
  userId: string,
  limit = 20,
  cursor?: string,
) {
  return prisma.notification.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    take: limit,
    ...(cursor
      ? {
          skip: 1,
          cursor: { id: cursor },
        }
      : {}),
  });
}

/**
 * Mark a single notification as read
 */
export async function markAsRead(notificationId: string, userId: string) {
  return prisma.notification.updateMany({
    where: {
      id: notificationId,
      userId, // Ensure user owns this notification
    },
    data: { isRead: true },
  });
}

/**
 * Mark all notifications as read for a user
 */
export async function markAllAsRead(userId: string) {
  return prisma.notification.updateMany({
    where: {
      userId,
      isRead: false,
    },
    data: { isRead: true },
  });
}

/**
 * Get unread count for a user
 */
export async function getUnreadCount(userId: string): Promise<number> {
  return prisma.notification.count({
    where: {
      userId,
      isRead: false,
    },
  });
}

/**
 * Auto-cleanup: delete old read notifications (older than 7 days)
 * and old unread notifications (older than 30 days)
 * Call this periodically (e.g. once per hour or on each poll)
 */
export async function cleanupOldNotifications(): Promise<number> {
  const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
  const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

  const [readResult, unreadResult] = await Promise.all([
    // Delete read notifications older than 7 days
    prisma.notification.deleteMany({
      where: {
        isRead: true,
        createdAt: { lt: sevenDaysAgo },
      },
    }),
    // Delete unread notifications older than 30 days
    prisma.notification.deleteMany({
      where: {
        isRead: false,
        createdAt: { lt: thirtyDaysAgo },
      },
    }),
  ]);

  const total = readResult.count + unreadResult.count;
  if (total > 0) {
    console.log(
      `[Notification] Cleanup: deleted ${readResult.count} read + ${unreadResult.count} unread old notifications`,
    );
  }
  return total;
}

/**
 * Create notification when reservation status changes (for customer)
 */
export async function notifyReservationStatusChange(params: {
  customerId: string;
  reservationId: string;
  queueNumber: number;
  vendorName: string;
  newStatus: string;
}) {
  const { customerId, reservationId, queueNumber, vendorName, newStatus } =
    params;
  const statusLabel = STATUS_LABELS[newStatus] || newStatus;
  const emoji = STATUS_EMOJI[newStatus] || "📋";

  let body = "";
  switch (newStatus) {
    case "CONFIRMED":
      body = `ร้าน ${vendorName} ยืนยันคำสั่งซื้อของคุณแล้ว`;
      break;
    case "PREPARING":
      body = `ร้าน ${vendorName} กำลังเตรียมอาหารของคุณ`;
      break;
    case "READY":
      body = `อาหารจากร้าน ${vendorName} พร้อมรับแล้ว! มารับได้เลย`;
      break;
    case "COMPLETED":
      body = `คำสั่งซื้อจากร้าน ${vendorName} เสร็จสิ้น ขอบคุณค่ะ`;
      break;
    case "CANCELLED":
      body = `คำสั่งซื้อจากร้าน ${vendorName} ถูกยกเลิก`;
      break;
    default:
      body = `สถานะคำสั่งซื้อจากร้าน ${vendorName} เปลี่ยนเป็น ${statusLabel}`;
  }

  return createNotification({
    userId: customerId,
    title: `${emoji} คิว #${queueNumber} — ${statusLabel}`,
    body,
    type: "reservation_status",
    data: {
      reservationId,
      queueNumber,
      vendorName,
      status: newStatus,
    },
  });
}

/**
 * Create notification when new reservation is placed (for vendor owner)
 */
export async function notifyNewReservation(params: {
  vendorUserId: string;
  reservationId: string;
  queueNumber: number;
  customerName: string;
  totalAmount: number;
}) {
  const {
    vendorUserId,
    reservationId,
    queueNumber,
    customerName,
    totalAmount,
  } = params;

  return createNotification({
    userId: vendorUserId,
    title: `🆕 คำสั่งซื้อใหม่ — คิว #${queueNumber}`,
    body: `${customerName} สั่งอาหาร ฿${totalAmount} (คิว #${queueNumber})`,
    type: "new_reservation",
    data: {
      reservationId,
      queueNumber,
      customerName,
      totalAmount,
    },
  });
}
