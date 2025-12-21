// Time Slot Service
import { prisma } from '../config/database';
import { NotFoundError, ForbiddenError } from '../utils/errors';
import type { CreateTimeSlotInput } from '../utils/validation';
import type { Role, Period } from '@prisma/client';

export interface TimeSlotResponse {
  id: string;
  vendorId: string | null;
  label: string;
  startTime: string;
  endTime: string;
  period: Period;
  isActive: boolean;
  maxOrders: number;
  createdAt: Date;
  updatedAt: Date;
}

/**
 * Create time slot
 */
export async function createTimeSlot(
  vendorId: string | null,
  userId: string,
  userRole: Role,
  input: CreateTimeSlotInput
): Promise<TimeSlotResponse> {
  // If vendorId is provided, verify permission
  if (vendorId) {
    const vendor = await prisma.vendor.findUnique({
      where: { id: vendorId },
    });

    if (!vendor) {
      throw new NotFoundError('Vendor');
    }

    if (vendor.userId !== userId && userRole !== 'ADMIN') {
      throw new ForbiddenError('Not authorized to create time slots for this vendor');
    }
  } else if (userRole !== 'ADMIN') {
    throw new ForbiddenError('Only admin can create global time slots');
  }

  const timeSlot = await prisma.timeSlot.create({
    data: {
      vendorId,
      label: input.label,
      startTime: input.startTime,
      endTime: input.endTime,
      period: input.period,
      maxOrders: input.maxOrders,
    },
  });

  return timeSlot;
}

/**
 * Get time slots (global or vendor-specific)
 */
export async function getTimeSlots(vendorId?: string): Promise<TimeSlotResponse[]> {
  const timeSlots = await prisma.timeSlot.findMany({
    where: {
      OR: [
        { vendorId: null }, // Global time slots
        { vendorId: vendorId || undefined }, // Vendor-specific
      ],
      isActive: true,
    },
    orderBy: [{ period: 'asc' }, { startTime: 'asc' }],
  });

  return timeSlots;
}

/**
 * Get time slot by ID
 */
export async function getTimeSlotById(timeSlotId: string): Promise<TimeSlotResponse> {
  const timeSlot = await prisma.timeSlot.findUnique({
    where: { id: timeSlotId },
  });

  if (!timeSlot) {
    throw new NotFoundError('Time slot');
  }

  return timeSlot;
}

/**
 * Update time slot
 */
export async function updateTimeSlot(
  timeSlotId: string,
  userId: string,
  userRole: Role,
  input: Partial<CreateTimeSlotInput & { isActive: boolean }>
): Promise<TimeSlotResponse> {
  const timeSlot = await prisma.timeSlot.findUnique({
    where: { id: timeSlotId },
    include: { vendor: true },
  });

  if (!timeSlot) {
    throw new NotFoundError('Time slot');
  }

  // Check permission
  if (timeSlot.vendor) {
    if (timeSlot.vendor.userId !== userId && userRole !== 'ADMIN') {
      throw new ForbiddenError('Not authorized to update this time slot');
    }
  } else if (userRole !== 'ADMIN') {
    throw new ForbiddenError('Only admin can update global time slots');
  }

  const updated = await prisma.timeSlot.update({
    where: { id: timeSlotId },
    data: {
      label: input.label,
      startTime: input.startTime,
      endTime: input.endTime,
      period: input.period,
      maxOrders: input.maxOrders,
      isActive: input.isActive,
    },
  });

  return updated;
}

/**
 * Delete time slot
 */
export async function deleteTimeSlot(
  timeSlotId: string,
  userId: string,
  userRole: Role
): Promise<void> {
  const timeSlot = await prisma.timeSlot.findUnique({
    where: { id: timeSlotId },
    include: { vendor: true },
  });

  if (!timeSlot) {
    throw new NotFoundError('Time slot');
  }

  // Check permission
  if (timeSlot.vendor) {
    if (timeSlot.vendor.userId !== userId && userRole !== 'ADMIN') {
      throw new ForbiddenError('Not authorized to delete this time slot');
    }
  } else if (userRole !== 'ADMIN') {
    throw new ForbiddenError('Only admin can delete global time slots');
  }

  await prisma.timeSlot.delete({ where: { id: timeSlotId } });
}

/**
 * Get available time slots for a vendor (considering capacity)
 */
export async function getAvailableTimeSlots(
  vendorId: string,
  date: string
): Promise<(TimeSlotResponse & { availableSlots: number; totalReservations: number })[]> {
  const startDate = new Date(date);
  startDate.setHours(0, 0, 0, 0);
  const endDate = new Date(date);
  endDate.setHours(23, 59, 59, 999);

  const timeSlots = await prisma.timeSlot.findMany({
    where: {
      OR: [{ vendorId: null }, { vendorId }],
      isActive: true,
    },
    include: {
      reservations: {
        where: {
          vendorId,
          createdAt: {
            gte: startDate,
            lte: endDate,
          },
          status: {
            notIn: ['CANCELLED'],
          },
        },
      },
    },
    orderBy: [{ period: 'asc' }, { startTime: 'asc' }],
  });

  return timeSlots.map((slot) => ({
    ...slot,
    totalReservations: slot.reservations.length,
    availableSlots: slot.maxOrders - slot.reservations.length,
  }));
}
