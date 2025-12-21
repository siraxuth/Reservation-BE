#!/usr/bin/env bun
// Admin Account Creation CLI
// Usage: bun run create-admin
// Or: bun run src/scripts/create-admin.ts

import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';
import bcrypt from 'bcryptjs';
import { createInterface } from 'readline';
import { validateStrongPassword } from '../utils/validation';

// Ensure DATABASE_URL is loaded
if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL environment variable is not set');
  process.exit(1);
}

// Create Prisma client
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
const adapter = new PrismaPg(pool);
const prisma = new PrismaClient({ adapter });

// Create readline interface
const rl = createInterface({
  input: process.stdin,
  output: process.stdout,
});

// Promisified question helper
function question(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    rl.question(prompt, (answer) => {
      resolve(answer);
    });
  });
}

// Hidden password input (shows asterisks)
async function questionHidden(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    process.stdout.write(prompt);

    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;

    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding('utf8');

    let password = '';

    const onData = (char: string) => {
      // Enter key
      if (char === '\n' || char === '\r' || char === '\u0004') {
        stdin.setRawMode(wasRaw);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(password);
        return;
      }

      // Ctrl+C
      if (char === '\u0003') {
        console.log('\n\nOperation cancelled.');
        process.exit(1);
      }

      // Backspace
      if (char === '\u007f' || char === '\b') {
        if (password.length > 0) {
          password = password.slice(0, -1);
          process.stdout.clearLine(0);
          process.stdout.cursorTo(0);
          process.stdout.write(prompt + '*'.repeat(password.length));
        }
        return;
      }

      // Regular character
      password += char;
      process.stdout.write('*');
    };

    stdin.on('data', onData);
  });
}

async function main() {
  console.log('\n╔════════════════════════════════════════════════╗');
  console.log('║         Admin Account Creation Tool            ║');
  console.log('╚════════════════════════════════════════════════╝\n');

  // Check for existing admins
  const existingAdmins = await prisma.user.count({ where: { role: 'ADMIN' } });
  if (existingAdmins > 0) {
    console.log(`Note: ${existingAdmins} admin account(s) already exist.\n`);
  }

  // Collect email
  const email = await question('Email: ');

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    console.error('\nError: Invalid email format');
    process.exit(1);
  }

  // Check if email exists
  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) {
    console.error('\nError: A user with this email already exists');
    process.exit(1);
  }

  // Collect name
  const name = await question('Full Name: ');
  if (name.trim().length < 2) {
    console.error('\nError: Name must be at least 2 characters');
    process.exit(1);
  }

  // Collect phone (optional)
  const phone = await question('Phone (optional, press Enter to skip): ');

  // Show password requirements
  console.log('\n┌────────────────────────────────────────────────┐');
  console.log('│ Password Requirements:                         │');
  console.log('│   • Minimum 12 characters                      │');
  console.log('│   • At least one uppercase letter (A-Z)        │');
  console.log('│   • At least one lowercase letter (a-z)        │');
  console.log('│   • At least one number (0-9)                  │');
  console.log('│   • At least one special character (!@#$%^&*)  │');
  console.log('└────────────────────────────────────────────────┘\n');

  // Collect password
  const password = await questionHidden('Password: ');

  // Validate password strength
  const validation = validateStrongPassword(password);
  if (!validation.valid) {
    console.error('\nError: Password does not meet requirements:');
    validation.errors.forEach((err) => console.error(`  • ${err}`));
    process.exit(1);
  }

  // Confirm password
  const confirmPassword = await questionHidden('Confirm Password: ');
  if (password !== confirmPassword) {
    console.error('\nError: Passwords do not match');
    process.exit(1);
  }

  console.log('\nCreating admin account...');

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 12);

  // Create admin user
  const admin = await prisma.user.create({
    data: {
      email,
      name: name.trim(),
      phone: phone.trim() || null,
      password: hashedPassword,
      role: 'ADMIN',
      isActive: true,
      emailVerified: true, // Admin accounts are pre-verified
    },
  });

  // Create audit log
  await prisma.auditLog.create({
    data: {
      userId: admin.id,
      action: 'ADMIN_CREATED',
      entity: 'User',
      entityId: admin.id,
      metadata: {
        createdBy: 'CLI',
        createdAt: new Date().toISOString(),
      },
    },
  });

  console.log('\n╔════════════════════════════════════════════════╗');
  console.log('║      Admin Account Created Successfully!       ║');
  console.log('╚════════════════════════════════════════════════╝');
  console.log(`\n  Email: ${admin.email}`);
  console.log(`  Name:  ${admin.name}`);
  console.log(`  ID:    ${admin.id}`);
  console.log(`  Role:  ADMIN`);
  console.log('\n  You can now login at your application.\n');

  rl.close();
  await prisma.$disconnect();
  process.exit(0);
}

main().catch(async (err) => {
  console.error('\nError:', err.message);
  await prisma.$disconnect();
  process.exit(1);
});
