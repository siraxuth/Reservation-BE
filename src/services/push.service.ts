// Push Notification Service using Firebase Cloud Messaging (FCM) v1 HTTP API
// Sends native push notifications to Android, iOS (Safari 16.4+), and Web browsers

import { env } from "../config/env";
import { prisma } from "../config/database";

// FCM v1 API endpoint
const FCM_API_URL = `https://fcm.googleapis.com/v1/projects/${env.FCM_PROJECT_ID}/messages:send`;

// Cache for the access token
let cachedAccessToken: { token: string; expiresAt: number } | null = null;

/**
 * Check if FCM is configured
 */
export function isFCMConfigured(): boolean {
  return !!(env.FCM_PROJECT_ID && env.FCM_CLIENT_EMAIL && env.FCM_PRIVATE_KEY);
}

/**
 * Get OAuth2 access token for FCM v1 API using service account credentials
 * This uses the JWT-based authentication flow
 */
async function getAccessToken(): Promise<string> {
  // Return cached token if still valid (with 5 minute buffer)
  if (
    cachedAccessToken &&
    cachedAccessToken.expiresAt > Date.now() + 5 * 60 * 1000
  ) {
    return cachedAccessToken.token;
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = now + 3600; // 1 hour

  // Build JWT header and payload
  const header = { alg: "RS256", typ: "JWT" };
  const payload = {
    iss: env.FCM_CLIENT_EMAIL,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: exp,
  };

  // Base64URL encode
  const base64url = (obj: object) => {
    const json = JSON.stringify(obj);
    const base64 = Buffer.from(json).toString("base64");
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const headerEncoded = base64url(header);
  const payloadEncoded = base64url(payload);
  const signInput = `${headerEncoded}.${payloadEncoded}`;

  // Sign with RSA private key
  const privateKey = env.FCM_PRIVATE_KEY.replace(/\\n/g, "\n");
  const crypto = await import("crypto");
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(signInput);
  const signature = sign
    .sign(privateKey, "base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  const jwt = `${signInput}.${signature}`;

  // Exchange JWT for access token
  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  if (!response.ok) {
    const error = await response.text();
    console.error("[FCM] Failed to get access token:", error);
    throw new Error("Failed to get FCM access token");
  }

  const data = (await response.json()) as {
    access_token: string;
    expires_in: number;
  };
  cachedAccessToken = {
    token: data.access_token,
    expiresAt: Date.now() + data.expires_in * 1000,
  };

  return data.access_token;
}

/**
 * Register a push subscription token for a user
 */
export async function registerToken(
  userId: string,
  token: string,
  device?: string,
  userAgent?: string,
): Promise<void> {
  await prisma.pushSubscription.upsert({
    where: { token },
    create: {
      userId,
      token,
      device: device || "web",
      userAgent,
      isActive: true,
    },
    update: {
      userId,
      device: device || "web",
      userAgent,
      isActive: true,
      updatedAt: new Date(),
    },
  });
  console.log(`[FCM] Token registered for user ${userId} (${device || "web"})`);
}

/**
 * Unregister a push subscription token
 */
export async function unregisterToken(token: string): Promise<void> {
  await prisma.pushSubscription.updateMany({
    where: { token },
    data: { isActive: false },
  });
  console.log(`[FCM] Token unregistered`);
}

/**
 * Remove all tokens for a user
 */
export async function removeAllTokensForUser(userId: string): Promise<void> {
  await prisma.pushSubscription.updateMany({
    where: { userId },
    data: { isActive: false },
  });
}

/**
 * Send push notification to a single FCM token using v1 API
 */
async function sendToToken(
  token: string,
  title: string,
  body: string,
  data?: Record<string, string>,
  icon?: string,
): Promise<boolean> {
  if (!isFCMConfigured()) {
    console.warn("[FCM] Not configured, skipping push notification");
    return false;
  }

  try {
    const accessToken = await getAccessToken();

    const message: any = {
      message: {
        token,
        notification: {
          title,
          body,
        },
        webpush: {
          notification: {
            title,
            body,
            icon: icon || "/android-chrome-192x192.png",
            badge: "/favicon-32x32.png",
            vibrate: [200, 100, 200],
            requireInteraction: true,
            actions: [
              { action: "open", title: "เปิดดู" },
              { action: "dismiss", title: "ปิด" },
            ],
          },
          fcm_options: {
            link: data?.url || "/",
          },
        },
        android: {
          priority: "high",
          notification: {
            title,
            body,
            icon: "ic_notification",
            color: "#f97316",
            sound: "default",
            channel_id: "reservation_updates",
            click_action: "OPEN_RESERVATION",
          },
        },
        apns: {
          payload: {
            aps: {
              alert: { title, body },
              badge: 1,
              sound: "default",
              "mutable-content": 1,
            },
          },
          fcm_options: {
            image: icon || undefined,
          },
        },
        data: data || {},
      },
    };

    const response = await fetch(FCM_API_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(message),
    });

    if (!response.ok) {
      const error = await response.text();
      console.error(`[FCM] Failed to send to token:`, error);

      // If token is invalid, mark it as inactive
      if (response.status === 404 || response.status === 400) {
        await prisma.pushSubscription.updateMany({
          where: { token },
          data: { isActive: false },
        });
        console.log(`[FCM] Removed invalid token`);
      }

      return false;
    }

    return true;
  } catch (error) {
    console.error(`[FCM] Error sending notification:`, error);
    return false;
  }
}

/**
 * Send push notification to all devices of a user
 */
export async function sendToUser(
  userId: string,
  title: string,
  body: string,
  data?: Record<string, string>,
  icon?: string,
): Promise<number> {
  const subscriptions = await prisma.pushSubscription.findMany({
    where: { userId, isActive: true },
  });

  if (subscriptions.length === 0) {
    console.log(`[FCM] No active subscriptions for user ${userId}`);
    return 0;
  }

  let sentCount = 0;
  const sendPromises = subscriptions.map(async (sub: { token: string }) => {
    const ok = await sendToToken(sub.token, title, body, data, icon);
    if (ok) sentCount++;
  });

  await Promise.allSettled(sendPromises);
  console.log(
    `[FCM] Sent ${sentCount}/${subscriptions.length} notifications to user ${userId}`,
  );
  return sentCount;
}

/**
 * Send push notification to multiple users
 */
export async function sendToUsers(
  userIds: string[],
  title: string,
  body: string,
  data?: Record<string, string>,
  icon?: string,
): Promise<number> {
  let totalSent = 0;
  const sendPromises = userIds.map(async (userId) => {
    const sent = await sendToUser(userId, title, body, data, icon);
    totalSent += sent;
  });

  await Promise.allSettled(sendPromises);
  return totalSent;
}

// ===========================================
// Predefined notification templates
// ===========================================

const STATUS_NOTIFICATIONS: Record<
  string,
  { title: string; body: (queueNumber: number, vendorName: string) => string }
> = {
  CONFIRMED: {
    title: "✅ ยืนยันคำสั่งซื้อแล้ว",
    body: (q, v) => `คำสั่งซื้อ #${q} จากร้าน ${v} ได้รับการยืนยันแล้ว`,
  },
  PREPARING: {
    title: "👨‍🍳 กำลังเตรียมอาหาร",
    body: (q, v) => `ร้าน ${v} กำลังเตรียมคำสั่งซื้อ #${q} ของคุณ`,
  },
  READY: {
    title: "🔔 อาหารพร้อมแล้ว!",
    body: (q, v) => `คำสั่งซื้อ #${q} จากร้าน ${v} พร้อมรับแล้ว มารับได้เลย!`,
  },
  COMPLETED: {
    title: "🎉 เสร็จสมบูรณ์",
    body: (q, v) =>
      `คำสั่งซื้อ #${q} จากร้าน ${v} เสร็จสมบูรณ์แล้ว ขอบคุณครับ!`,
  },
  CANCELLED: {
    title: "❌ คำสั่งซื้อถูกยกเลิก",
    body: (q, v) => `คำสั่งซื้อ #${q} จากร้าน ${v} ถูกยกเลิก`,
  },
};

/**
 * Send push notification for reservation status change
 */
export async function sendReservationStatusNotification(
  customerId: string,
  status: string,
  queueNumber: number,
  vendorName: string,
  reservationId: string,
): Promise<void> {
  const template = STATUS_NOTIFICATIONS[status];
  if (!template) return;

  const data = {
    type: "reservation_status",
    reservationId,
    status,
    queueNumber: String(queueNumber),
    url: "/reservation",
  };

  await sendToUser(
    customerId,
    template.title,
    template.body(queueNumber, vendorName),
    data,
  );
}

/**
 * Send push notification for new reservation (to vendor)
 */
export async function sendNewReservationNotification(
  vendorUserId: string,
  queueNumber: number,
  customerName: string,
  totalAmount: number,
  reservationId: string,
): Promise<void> {
  await sendToUser(
    vendorUserId,
    "🆕 คำสั่งซื้อใหม่!",
    `${customerName} สั่ง #${queueNumber} (฿${totalAmount.toLocaleString()})`,
    {
      type: "new_reservation",
      reservationId,
      queueNumber: String(queueNumber),
      url: "/vendor",
    },
  );
}
