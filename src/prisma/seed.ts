// Database Seed Script - Production Ready
// Run with: bun run db:seed
// This script only creates reference data, NOT user accounts
// Use `bun run create-admin` to create admin accounts

import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';

// Ensure DATABASE_URL is loaded
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL environment variable is not set');
  console.error('Please ensure .env file exists with DATABASE_URL');
  process.exit(1);
}

// Safety check - prevent accidental data deletion in production
const isProduction = process.env.NODE_ENV === 'production';

// Create pg Pool and Prisma adapter for Prisma 7
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

async function main() {
  console.log('Starting database seed...\n');

  if (isProduction) {
    console.log('[Production Mode] Only upserting reference data (no data deletion)');
  }

  // ============================================
  // Payment Methods (Reference Data)
  // ============================================
  console.log('Seeding payment methods...');

  await prisma.paymentMethod.upsert({
    where: { type: 'CASH' },
    update: {},
    create: {
      type: 'CASH',
      label: 'เงินสด',
      description: 'ชำระเงินสดที่ร้าน',
      icon: 'banknote',
      isActive: true,
    },
  });

  await prisma.paymentMethod.upsert({
    where: { type: 'BANK_TRANSFER' },
    update: {},
    create: {
      type: 'BANK_TRANSFER',
      label: 'โอนเงิน',
      description: 'โอนเงินผ่านธนาคาร / พร้อมเพย์',
      icon: 'smartphone',
      isActive: true,
    },
  });

  console.log('  Payment methods seeded');

  // ============================================
  // Time Slots (Reference Data)
  // ============================================
  console.log('Seeding time slots...');

  const timeSlotData = [
    {
      id: 'global-07:00-09:00',
      label: 'เช้า 07:00 - 09:00',
      startTime: '07:00',
      endTime: '09:00',
      period: 'MORNING' as const,
      maxOrders: 50,
    },
    {
      id: 'global-09:00-11:00',
      label: 'เช้า 09:00 - 11:00',
      startTime: '09:00',
      endTime: '11:00',
      period: 'MORNING' as const,
      maxOrders: 50,
    },
    {
      id: 'global-11:00-13:00',
      label: 'เที่ยง 11:00 - 13:00',
      startTime: '11:00',
      endTime: '13:00',
      period: 'AFTERNOON' as const,
      maxOrders: 100,
    },
    {
      id: 'global-13:00-15:00',
      label: 'บ่าย 13:00 - 15:00',
      startTime: '13:00',
      endTime: '15:00',
      period: 'AFTERNOON' as const,
      maxOrders: 50,
    },
  ];

  for (const slot of timeSlotData) {
    await prisma.timeSlot.upsert({
      where: { id: slot.id },
      update: {
        label: slot.label,
        startTime: slot.startTime,
        endTime: slot.endTime,
        period: slot.period,
        maxOrders: slot.maxOrders,
        isActive: true,
      },
      create: {
        id: slot.id,
        label: slot.label,
        startTime: slot.startTime,
        endTime: slot.endTime,
        period: slot.period,
        maxOrders: slot.maxOrders,
        isActive: true,
      },
    });
  }

  console.log('  Time slots seeded');

  // ============================================
  // Summary
  // ============================================
  console.log(`
=====================================================
  Database seeded successfully!
=====================================================

Reference data created:
  - Payment methods: 2 (CASH, BANK_TRANSFER)
  - Time slots: 4 (global time slots)

Next steps:
  1. Create an admin account:
     bun run create-admin

  2. Start the server:
     bun run dev

  3. Vendors and customers can register through the app
=====================================================
`);
}

main()
  .catch((e) => {
    console.error('Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
