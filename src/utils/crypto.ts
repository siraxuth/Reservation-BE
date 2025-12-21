// Cryptography Utilities
import { nanoid } from 'nanoid';
import bcrypt from 'bcryptjs';
import { env } from '../config/env';

/**
 * Generate a secure random ID
 */
export function generateId(length: number = 21): string {
  return nanoid(length);
}

/**
 * Generate API Key
 */
export function generateApiKey(): { key: string; prefix: string } {
  const key = `${env.API_KEY_PREFIX}${nanoid(env.API_KEY_LENGTH)}`;
  const prefix = key.substring(0, 8);
  return { key, prefix };
}

/**
 * Hash password
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password, 12);
}

/**
 * Compare password with hash
 */
export async function comparePassword(
  password: string,
  hash: string
): Promise<boolean> {
  return bcrypt.compare(password, hash);
}

/**
 * Generate session token
 */
export function generateSessionToken(): string {
  return nanoid(64);
}

/**
 * Generate queue number for a specific date
 */
export function generateQueueNumber(vendorId: string, date: Date): number {
  // In production, this should query the database to get the next queue number
  // For now, we use timestamp-based generation
  const dateString = date.toISOString().split('T')[0];
  const timestamp = Date.now();
  return parseInt(`${timestamp}`.slice(-4), 10);
}
