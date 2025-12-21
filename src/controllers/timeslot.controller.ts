// Time Slot Controller
import { Elysia, t } from 'elysia';
import * as timeSlotService from '../services/timeslot.service';
import {
  authPlugin,
  requireAuth,
  requireVendorOrAdmin,
  requireAdmin,
  type AuthUser,
} from '../middlewares/auth.middleware';
import { success } from '../utils/response';
import { createTimeSlotSchema } from '../utils/validation';
import { BadRequestError } from '../utils/errors';

// Type helper for authenticated context
type AuthCtx = { user: AuthUser };

export const timeSlotController = new Elysia({ prefix: '/time-slots' })
  .use(authPlugin)

  // Get all time slots (public)
  .get(
    '/',
    async ({ query }) => {
      const timeSlots = await timeSlotService.getTimeSlots(query.vendorId);
      return success(timeSlots);
    },
    {
      query: t.Object({
        vendorId: t.Optional(t.String()),
      }),
      detail: {
        tags: ['Time Slots'],
        summary: 'Get time slots',
        description: 'Get all active time slots',
      },
    }
  )

  // Get available time slots for a vendor
  .get(
    '/available',
    async ({ query }) => {
      if (!query.vendorId || !query.date) {
        throw new BadRequestError('vendorId and date are required');
      }
      const timeSlots = await timeSlotService.getAvailableTimeSlots(
        query.vendorId,
        query.date
      );
      return success(timeSlots);
    },
    {
      query: t.Object({
        vendorId: t.String(),
        date: t.String(),
      }),
      detail: {
        tags: ['Time Slots'],
        summary: 'Get available slots',
        description: 'Get available time slots for a vendor on a specific date',
      },
    }
  )

  // Get time slot by ID
  .get(
    '/:timeSlotId',
    async ({ params }) => {
      const timeSlot = await timeSlotService.getTimeSlotById(params.timeSlotId);
      return success(timeSlot);
    },
    {
      params: t.Object({
        timeSlotId: t.String(),
      }),
      detail: {
        tags: ['Time Slots'],
        summary: 'Get time slot',
        description: 'Get time slot details',
      },
    }
  )

  // Protected routes
  .use(requireAuth)
  .use(requireVendorOrAdmin)

  // Create time slot for a vendor
  .post(
    '/',
    async (ctx) => {
      const { user, body } = ctx as unknown as AuthCtx & { body: any };
      const validated = createTimeSlotSchema.safeParse(body);
      if (!validated.success) {
        throw new BadRequestError(validated.error.errors[0].message);
      }

      const timeSlot = await timeSlotService.createTimeSlot(
        body.vendorId || null,
        user.id,
        user.role,
        validated.data
      );
      return success(timeSlot, 'Time slot created');
    },
    {
      body: t.Object({
        vendorId: t.Optional(t.String()),
        label: t.String(),
        startTime: t.String(),
        endTime: t.String(),
        period: t.Union([t.Literal('MORNING'), t.Literal('AFTERNOON')]),
        maxOrders: t.Optional(t.Number()),
      }),
      detail: {
        tags: ['Time Slots'],
        summary: 'Create time slot',
        description: 'Create a new time slot',
      },
    }
  )

  // Update time slot
  .patch(
    '/:timeSlotId',
    async (ctx) => {
      const { user, params, body } = ctx as unknown as AuthCtx & { params: { timeSlotId: string }; body: any };
      const timeSlot = await timeSlotService.updateTimeSlot(
        params.timeSlotId,
        user.id,
        user.role,
        body
      );
      return success(timeSlot, 'Time slot updated');
    },
    {
      params: t.Object({
        timeSlotId: t.String(),
      }),
      body: t.Object({
        label: t.Optional(t.String()),
        startTime: t.Optional(t.String()),
        endTime: t.Optional(t.String()),
        period: t.Optional(t.Union([t.Literal('MORNING'), t.Literal('AFTERNOON')])),
        maxOrders: t.Optional(t.Number()),
        isActive: t.Optional(t.Boolean()),
      }),
      detail: {
        tags: ['Time Slots'],
        summary: 'Update time slot',
        description: 'Update time slot details',
      },
    }
  )

  // Delete time slot
  .delete(
    '/:timeSlotId',
    async (ctx) => {
      const { user, params } = ctx as unknown as AuthCtx & { params: { timeSlotId: string } };
      await timeSlotService.deleteTimeSlot(params.timeSlotId, user.id, user.role);
      return success(null, 'Time slot deleted');
    },
    {
      params: t.Object({
        timeSlotId: t.String(),
      }),
      detail: {
        tags: ['Time Slots'],
        summary: 'Delete time slot',
        description: 'Delete a time slot',
      },
    }
  );
