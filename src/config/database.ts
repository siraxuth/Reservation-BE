// Database Configuration
// Prisma Client Singleton for Bun Runtime with Prisma 7

import { PrismaClient } from '@prisma/client';
import { PrismaPg } from '@prisma/adapter-pg';
import pg from 'pg';
import { env } from './env';

declare global {
  var prisma: PrismaClient | undefined;
}

// Lazy initialization - don't create connection on import
let _prisma: PrismaClient | undefined;

export function getPrisma(): PrismaClient {
  if (!_prisma) {
    const pool = new pg.Pool({ connectionString: env.DATABASE_URL });
    const adapter = new PrismaPg(pool);
    _prisma = new PrismaClient({
      adapter,
      log: ['error'],
    });
  }
  return _prisma;
}

// For backward compatibility - lazy getter
export const prisma = new Proxy({} as PrismaClient, {
  get(_, prop) {
    return (getPrisma() as any)[prop];
  },
});

export default prisma;
