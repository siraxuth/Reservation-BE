// Reservation Service
import { prisma } from "../config/database";
import {
  sendReservationStatusNotification,
  sendNewReservationNotification,
} from "./push.service";
import {
  notifyReservationStatusChange,
  notifyNewReservation,
} from "./notification.service";
import {
  NotFoundError,
  ForbiddenError,
  BadRequestError,
} from "../utils/errors";
import { parsePagination, createPaginationMeta } from "../utils/response";
import type {
  CreateReservationInput,
  PaginationInput,
} from "../utils/validation";
import type { Role, ReservationStatus } from "@prisma/client";
import {
  sendOrderConfirmedEmail,
  sendOrderPreparingEmail,
  sendOrderReadyEmail,
  sendOrderCompletedEmail,
  sendOrderCancelledEmail,
} from "./email.service";

export interface ReservationResponse {
  id: string;
  customerId: string;
  vendorId: string;
  timeSlotId: string;
  customerName: string;
  customerContact: string;
  paymentMethod: string;
  status: ReservationStatus;
  totalAmount: number;
  queueNumber: number;
  notes: string | null;
  createdAt: Date;
  updatedAt: Date;
  confirmedAt: Date | null;
  completedAt: Date | null;
  items: {
    id: string;
    menuItemId: string;
    name: string;
    price: number;
    quantity: number;
  }[];
  vendor?: {
    id: string;
    name: string;
    image: string | null;
  };
  customer?: {
    id: string;
    name: string;
    email: string;
  };
  timeSlot?: {
    id: string;
    label: string;
    startTime: string;
    endTime: string;
    period: string;
  };
}

/**
 * Generate queue number for today
 */
async function generateQueueNumber(vendorId: string): Promise<number> {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const lastReservation = await prisma.reservation.findFirst({
    where: {
      vendorId,
      createdAt: { gte: today },
    },
    orderBy: { queueNumber: "desc" },
  });

  return (lastReservation?.queueNumber || 0) + 1;
}

/**
 * Create reservation
 */
export async function createReservation(
  customerId: string,
  input: CreateReservationInput,
): Promise<ReservationResponse> {
  // Verify vendor exists and is open
  const vendor = await prisma.vendor.findUnique({
    where: { id: input.vendorId },
  });

  if (!vendor) {
    throw new NotFoundError("Vendor");
  }

  if (!vendor.isOpen) {
    throw new BadRequestError("This vendor is currently closed");
  }

  // Verify time slot exists
  const timeSlot = await prisma.timeSlot.findUnique({
    where: { id: input.timeSlotId },
  });

  if (!timeSlot) {
    throw new NotFoundError("Time slot");
  }

  // Get menu items and calculate total
  const menuItemIds = input.items.map((item) => item.menuItemId);
  const menuItems = await prisma.menuItem.findMany({
    where: {
      id: { in: menuItemIds },
      vendorId: input.vendorId,
    },
  });

  if (menuItems.length !== menuItemIds.length) {
    throw new BadRequestError("Some menu items are not found or not available");
  }

  // Check all items are available
  const unavailableItems = menuItems.filter((item) => !item.isAvailable);
  if (unavailableItems.length > 0) {
    throw new BadRequestError(
      `Some items are not available: ${unavailableItems.map((i) => i.name).join(", ")}`,
    );
  }

  // Calculate total amount
  let totalAmount = 0;
  const reservationItems = input.items.map((inputItem) => {
    const menuItem = menuItems.find((m) => m.id === inputItem.menuItemId)!;
    const itemTotal = menuItem.price * inputItem.quantity;
    totalAmount += itemTotal;

    return {
      menuItemId: menuItem.id,
      name: menuItem.name,
      price: menuItem.price,
      quantity: inputItem.quantity,
    };
  });

  // Generate queue number
  const queueNumber = await generateQueueNumber(input.vendorId);

  // Create reservation with items
  const reservation = await prisma.reservation.create({
    data: {
      customerId,
      vendorId: input.vendorId,
      timeSlotId: input.timeSlotId,
      customerName: input.customerName,
      customerContact: input.customerContact,
      paymentMethod: input.paymentMethod,
      totalAmount,
      queueNumber,
      notes: input.notes,
      items: {
        create: reservationItems,
      },
    },
    include: {
      items: true,
      vendor: {
        select: {
          id: true,
          name: true,
          image: true,
        },
      },
      customer: {
        select: {
          id: true,
          name: true,
          email: true,
        },
      },
      timeSlot: {
        select: {
          id: true,
          label: true,
          startTime: true,
          endTime: true,
          period: true,
        },
      },
    },
  });

  // Update vendor total orders
  await prisma.vendor.update({
    where: { id: input.vendorId },
    data: { totalOrders: { increment: 1 } },
  });

  // Send push notification to vendor about new order (fire and forget)
  if (vendor.userId) {
    sendNewReservationNotification(
      vendor.userId,
      reservation.queueNumber,
      reservation.customerName,
      reservation.totalAmount,
      reservation.id,
    ).catch((error: unknown) => {
      console.error(`[Push] Failed to notify vendor:`, error);
    });

    // Create in-app notification for vendor (always works)
    notifyNewReservation({
      vendorUserId: vendor.userId,
      reservationId: reservation.id,
      queueNumber: reservation.queueNumber,
      customerName: reservation.customerName,
      totalAmount: reservation.totalAmount,
    }).catch((error: unknown) => {
      console.error(
        `[Notification] Failed to create vendor notification:`,
        error,
      );
    });
  }

  return reservation;
}

/**
 * Get reservation by ID
 */
export async function getReservationById(
  reservationId: string,
  userId: string,
  userRole: Role,
): Promise<ReservationResponse> {
  const reservation = await prisma.reservation.findUnique({
    where: { id: reservationId },
    include: {
      items: true,
      vendor: {
        select: {
          id: true,
          name: true,
          image: true,
          userId: true,
        },
      },
      customer: {
        select: {
          id: true,
          name: true,
          email: true,
        },
      },
      timeSlot: {
        select: {
          id: true,
          label: true,
          startTime: true,
          endTime: true,
          period: true,
        },
      },
    },
  });

  if (!reservation) {
    throw new NotFoundError("Reservation");
  }

  // Check permission
  const isOwner = reservation.customerId === userId;
  const isVendorOwner = (reservation.vendor as any)?.userId === userId;

  if (!isOwner && !isVendorOwner && userRole !== "ADMIN") {
    throw new ForbiddenError("Not authorized to view this reservation");
  }

  return reservation;
}

/**
 * Update reservation status
 */
export async function updateReservationStatus(
  reservationId: string,
  userId: string,
  userRole: Role,
  status: ReservationStatus,
): Promise<ReservationResponse> {
  const reservation = await prisma.reservation.findUnique({
    where: { id: reservationId },
    include: { vendor: true },
  });

  if (!reservation) {
    throw new NotFoundError("Reservation");
  }

  // Check permission - only vendor owner or admin can update status
  const isVendorOwner = reservation.vendor.userId === userId;
  if (!isVendorOwner && userRole !== "ADMIN") {
    throw new ForbiddenError("Not authorized to update this reservation");
  }

  // Admin can change status freely, vendor follows transition rules
  if (userRole !== "ADMIN") {
    // Validate status transition for non-admin
    const validTransitions: Record<ReservationStatus, ReservationStatus[]> = {
      PENDING: ["CONFIRMED", "CANCELLED"],
      CONFIRMED: ["PREPARING", "CANCELLED"],
      PREPARING: ["READY", "CANCELLED"],
      READY: ["COMPLETED", "CANCELLED"],
      COMPLETED: [],
      CANCELLED: [],
    };

    if (!validTransitions[reservation.status].includes(status)) {
      throw new BadRequestError(
        `Cannot change status from ${reservation.status} to ${status}`,
      );
    }
  }

  const updateData: any = { status };

  if (status === "CONFIRMED") {
    updateData.confirmedAt = new Date();
  } else if (status === "COMPLETED") {
    updateData.completedAt = new Date();
  }

  const updated = await prisma.reservation.update({
    where: { id: reservationId },
    data: updateData,
    include: {
      items: true,
      vendor: {
        select: {
          id: true,
          name: true,
          image: true,
        },
      },
      customer: {
        select: {
          id: true,
          name: true,
          email: true,
        },
      },
      timeSlot: {
        select: {
          id: true,
          label: true,
          startTime: true,
          endTime: true,
          period: true,
        },
      },
    },
  });

  // Send email notification based on status change
  if (updated.customer?.email) {
    const orderDetails = {
      queueNumber: updated.queueNumber,
      vendorName: updated.vendor?.name || "ร้านค้า",
      customerName: updated.customer.name,
      items: updated.items.map((item) => ({
        name: item.name,
        quantity: item.quantity,
        price: item.price,
      })),
      totalAmount: updated.totalAmount,
      timeSlot: updated.timeSlot
        ? `${updated.timeSlot.startTime} - ${updated.timeSlot.endTime}`
        : undefined,
    };

    // Send notification email (fire and forget - don't block response)
    (async () => {
      try {
        switch (status) {
          case "CONFIRMED":
            await sendOrderConfirmedEmail(
              updated.customer!.email,
              orderDetails,
            );
            break;
          case "PREPARING":
            await sendOrderPreparingEmail(
              updated.customer!.email,
              orderDetails,
            );
            break;
          case "READY":
            await sendOrderReadyEmail(updated.customer!.email, orderDetails);
            break;
          case "COMPLETED":
            await sendOrderCompletedEmail(
              updated.customer!.email,
              orderDetails,
            );
            break;
          case "CANCELLED":
            await sendOrderCancelledEmail(
              updated.customer!.email,
              orderDetails,
            );
            break;
        }
        console.log(
          `[Reservation] Status notification sent for order #${updated.queueNumber} (${status})`,
        );
      } catch (error) {
        console.error(
          `[Reservation] Failed to send status notification:`,
          error,
        );
      }
    })();
  }

  // Send push notification (fire and forget - don't block response)
  if (updated.customer?.id) {
    sendReservationStatusNotification(
      updated.customer.id,
      status,
      updated.queueNumber,
      updated.vendor?.name || "ร้านค้า",
      updated.id,
    ).catch((error) => {
      console.error(`[Push] Failed to send push notification:`, error);
    });
  }

  // Create in-app notification (polling-based, always works)
  if (updated.customer?.id) {
    notifyReservationStatusChange({
      customerId: updated.customer.id,
      reservationId: updated.id,
      queueNumber: updated.queueNumber,
      vendorName: updated.vendor?.name || "ร้านค้า",
      newStatus: status,
    }).catch((error: unknown) => {
      console.error(
        `[Notification] Failed to create in-app notification:`,
        error,
      );
    });
  }

  return updated;
}

/**
 * Cancel reservation (by customer)
 */
export async function cancelReservation(
  reservationId: string,
  userId: string,
  userRole: Role,
): Promise<ReservationResponse> {
  const reservation = await prisma.reservation.findUnique({
    where: { id: reservationId },
    include: { vendor: true },
  });

  if (!reservation) {
    throw new NotFoundError("Reservation");
  }

  // Check permission - customer, vendor owner, or admin
  const isOwner = reservation.customerId === userId;
  const isVendorOwner = reservation.vendor.userId === userId;

  if (!isOwner && !isVendorOwner && userRole !== "ADMIN") {
    throw new ForbiddenError("Not authorized to cancel this reservation");
  }

  // Can only cancel pending or confirmed reservations
  if (!["PENDING", "CONFIRMED"].includes(reservation.status)) {
    throw new BadRequestError(
      "Can only cancel pending or confirmed reservations",
    );
  }

  const updated = await prisma.reservation.update({
    where: { id: reservationId },
    data: { status: "CANCELLED" },
    include: {
      items: true,
      vendor: {
        select: {
          id: true,
          name: true,
          image: true,
        },
      },
      customer: {
        select: {
          id: true,
          name: true,
          email: true,
        },
      },
      timeSlot: {
        select: {
          id: true,
          label: true,
          startTime: true,
          endTime: true,
          period: true,
        },
      },
    },
  });

  // Send cancellation email notification
  if (updated.customer?.email) {
    const orderDetails = {
      queueNumber: updated.queueNumber,
      vendorName: updated.vendor?.name || "ร้านค้า",
      customerName: updated.customer.name,
      items: updated.items.map((item) => ({
        name: item.name,
        quantity: item.quantity,
        price: item.price,
      })),
      totalAmount: updated.totalAmount,
    };

    // Fire and forget
    sendOrderCancelledEmail(updated.customer.email, orderDetails).catch(
      (error) => {
        console.error(
          `[Reservation] Failed to send cancellation email:`,
          error,
        );
      },
    );
  }

  return updated;
}

/**
 * Get customer's reservations
 */
export async function getCustomerReservations(
  customerId: string,
  pagination: PaginationInput,
  filters?: {
    status?: ReservationStatus;
  },
) {
  const { page, limit, skip } = parsePagination(pagination);

  const where: any = { customerId };

  if (filters?.status) {
    where.status = filters.status;
  }

  const [reservations, total] = await Promise.all([
    prisma.reservation.findMany({
      where,
      include: {
        items: true,
        vendor: {
          select: {
            id: true,
            name: true,
            image: true,
          },
        },
        timeSlot: {
          select: {
            id: true,
            label: true,
            startTime: true,
            endTime: true,
            period: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
      skip,
      take: limit,
    }),
    prisma.reservation.count({ where }),
  ]);

  return {
    items: reservations,
    meta: createPaginationMeta(page, limit, total),
  };
}

/**
 * Get vendor's reservations
 */
export async function getVendorReservations(
  vendorId: string,
  userId: string,
  userRole: Role,
  pagination: PaginationInput,
  filters?: {
    status?: ReservationStatus;
    date?: string; // YYYY-MM-DD
  },
) {
  // Verify vendor access
  const vendor = await prisma.vendor.findUnique({
    where: { id: vendorId },
  });

  if (!vendor) {
    throw new NotFoundError("Vendor");
  }

  if (vendor.userId !== userId && userRole !== "ADMIN") {
    throw new ForbiddenError("Not authorized to view these reservations");
  }

  const { page, limit, skip } = parsePagination(pagination);

  const where: any = { vendorId };

  if (filters?.status) {
    where.status = filters.status;
  }

  if (filters?.date) {
    const startDate = new Date(filters.date);
    startDate.setHours(0, 0, 0, 0);
    const endDate = new Date(filters.date);
    endDate.setHours(23, 59, 59, 999);

    where.createdAt = {
      gte: startDate,
      lte: endDate,
    };
  }

  const [reservations, total] = await Promise.all([
    prisma.reservation.findMany({
      where,
      include: {
        items: true,
        customer: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
        timeSlot: {
          select: {
            id: true,
            label: true,
            startTime: true,
            endTime: true,
            period: true,
          },
        },
      },
      orderBy: [{ status: "asc" }, { queueNumber: "asc" }],
      skip,
      take: limit,
    }),
    prisma.reservation.count({ where }),
  ]);

  return {
    items: reservations,
    meta: createPaginationMeta(page, limit, total),
  };
}

/**
 * Get all reservations (admin)
 */
export async function getAllReservations(
  pagination: PaginationInput,
  filters?: {
    status?: ReservationStatus;
    vendorId?: string;
    date?: string;
  },
) {
  const { page, limit, skip } = parsePagination(pagination);

  const where: any = {};

  if (filters?.status) {
    where.status = filters.status;
  }

  if (filters?.vendorId) {
    where.vendorId = filters.vendorId;
  }

  if (filters?.date) {
    const startDate = new Date(filters.date);
    startDate.setHours(0, 0, 0, 0);
    const endDate = new Date(filters.date);
    endDate.setHours(23, 59, 59, 999);

    where.createdAt = {
      gte: startDate,
      lte: endDate,
    };
  }

  const [reservations, total] = await Promise.all([
    prisma.reservation.findMany({
      where,
      include: {
        items: true,
        vendor: {
          select: {
            id: true,
            name: true,
            image: true,
          },
        },
        customer: {
          select: {
            id: true,
            name: true,
            email: true,
          },
        },
        timeSlot: {
          select: {
            id: true,
            label: true,
            startTime: true,
            endTime: true,
            period: true,
          },
        },
      },
      orderBy: { createdAt: "desc" },
      skip,
      take: limit,
    }),
    prisma.reservation.count({ where }),
  ]);

  return {
    items: reservations,
    meta: createPaginationMeta(page, limit, total),
  };
}

/**
 * Get reservation statistics
 */
export async function getReservationStats(vendorId?: string) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const where: any = vendorId ? { vendorId } : {};

  const [
    total,
    pending,
    confirmed,
    preparing,
    ready,
    completed,
    cancelled,
    todayCount,
    todayRevenue,
  ] = await Promise.all([
    prisma.reservation.count({ where }),
    prisma.reservation.count({ where: { ...where, status: "PENDING" } }),
    prisma.reservation.count({ where: { ...where, status: "CONFIRMED" } }),
    prisma.reservation.count({ where: { ...where, status: "PREPARING" } }),
    prisma.reservation.count({ where: { ...where, status: "READY" } }),
    prisma.reservation.count({ where: { ...where, status: "COMPLETED" } }),
    prisma.reservation.count({ where: { ...where, status: "CANCELLED" } }),
    prisma.reservation.count({
      where: { ...where, createdAt: { gte: today } },
    }),
    prisma.reservation.aggregate({
      where: {
        ...where,
        status: "COMPLETED",
        createdAt: { gte: today },
      },
      _sum: { totalAmount: true },
    }),
  ]);

  return {
    total,
    byStatus: {
      pending,
      confirmed,
      preparing,
      ready,
      completed,
      cancelled,
    },
    today: {
      count: todayCount,
      revenue: todayRevenue._sum.totalAmount || 0,
    },
  };
}
