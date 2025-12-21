import "dotenv/config";
import { Elysia, t } from "elysia";
import { cors } from "@elysiajs/cors";
import { openapi } from "@elysiajs/openapi";
import logixlysia from "logixlysia";
import { Google } from "arctic";
import { PrismaClient } from "@prisma/client";
import { PrismaPg } from "@prisma/adapter-pg";
import pg from "pg";
import { nanoid } from "nanoid";
import bcrypt from "bcryptjs";
import nodemailer from "nodemailer";
import { randomUUID } from "crypto";
import { bearer } from "@elysiajs/bearer";
import { z } from "zod";
import { v2 as cloudinary } from "cloudinary";

//#region src/config/env.ts
const INSECURE_JWT_SECRETS = [
	"dev-secret-key-change-in-production",
	"secret",
	"jwt-secret",
	"changeme",
	"password",
	"123456"
];
const getEnv = (key, defaultValue) => {
	const value = process.env[key] || defaultValue;
	if (!value) throw new Error(`Missing required environment variable: ${key}`);
	return value;
};
const getEnvOptional = (key, defaultValue = "") => {
	const value = process.env[key];
	return value !== void 0 ? value : defaultValue;
};
const getEnvNumber = (key, defaultValue) => {
	const value = process.env[key];
	if (value) return parseInt(value, 10);
	if (defaultValue !== void 0) return defaultValue;
	throw new Error(`Missing required environment variable: ${key}`);
};
const getEnvBoolean = (key, defaultValue = false) => {
	const value = process.env[key];
	if (value === void 0) return defaultValue;
	return value.toLowerCase() === "true";
};
function validateProductionSecurity() {
	if (!(getEnv("NODE_ENV", "development") === "production")) {
		console.warn("\n[Security] Running in development mode - security checks relaxed\n");
		return;
	}
	const errors = [];
	const warnings = [];
	const jwtSecret = process.env.JWT_SECRET;
	if (!jwtSecret) errors.push("JWT_SECRET is required in production");
	else {
		if (INSECURE_JWT_SECRETS.includes(jwtSecret.toLowerCase())) errors.push("JWT_SECRET is using an insecure default value - please set a secure secret");
		if (jwtSecret.length < 32) errors.push("JWT_SECRET must be at least 32 characters long");
		if (new Set(jwtSecret).size < 10) warnings.push("JWT_SECRET has low character variety - consider using a more random value");
	}
	const frontendUrl = process.env.FRONTEND_URL;
	if (!frontendUrl || frontendUrl.includes("localhost")) errors.push("FRONTEND_URL must be set to production URL (not localhost)");
	if (!process.env.DATABASE_URL) errors.push("DATABASE_URL is required");
	if (!process.env.SMTP_HOST) warnings.push("SMTP_HOST not configured - email features will not work");
	if (warnings.length > 0) {
		console.warn("\n[Production Security Warnings]");
		warnings.forEach((w) => console.warn(`  - ${w}`));
	}
	if (errors.length > 0) {
		console.error("\n[CRITICAL: Production Security Errors]");
		errors.forEach((e) => console.error(`  - ${e}`));
		console.error("\nApplication cannot start with insecure configuration.");
		console.error("Please fix the above issues before deploying to production.\n");
		process.exit(1);
	}
	console.log("[Security] Production security validation passed\n");
}
validateProductionSecurity();
const env = {
	PORT: getEnvNumber("PORT", 3001),
	NODE_ENV: getEnv("NODE_ENV", "development"),
	IS_PRODUCTION: getEnv("NODE_ENV", "development") === "production",
	DATABASE_URL: getEnv("DATABASE_URL"),
	JWT_SECRET: getEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
	JWT_EXPIRES_IN: getEnv("JWT_EXPIRES_IN", "7d"),
	GOOGLE_CLIENT_ID: getEnvOptional("GOOGLE_CLIENT_ID"),
	GOOGLE_CLIENT_SECRET: getEnvOptional("GOOGLE_CLIENT_SECRET"),
	GOOGLE_CALLBACK_URL: getEnvOptional("GOOGLE_CALLBACK_URL", "http://localhost:3001/api/auth/google/callback"),
	CLOUDINARY_CLOUD_NAME: getEnvOptional("CLOUDINARY_CLOUD_NAME"),
	CLOUDINARY_API_KEY: getEnvOptional("CLOUDINARY_API_KEY"),
	CLOUDINARY_API_SECRET: getEnvOptional("CLOUDINARY_API_SECRET"),
	FRONTEND_URL: getEnv("FRONTEND_URL", "http://localhost:3000"),
	API_KEY_PREFIX: getEnv("API_KEY_PREFIX", "rk_"),
	API_KEY_LENGTH: getEnvNumber("API_KEY_LENGTH", 32),
	RATE_LIMIT_WINDOW_MS: getEnvNumber("RATE_LIMIT_WINDOW_MS", 6e4),
	RATE_LIMIT_MAX_REQUESTS: getEnvNumber("RATE_LIMIT_MAX_REQUESTS", 100),
	LOG_LEVEL: getEnv("LOG_LEVEL", "info"),
	ACCOUNT_LOCKOUT_THRESHOLD: getEnvNumber("ACCOUNT_LOCKOUT_THRESHOLD", 5),
	ACCOUNT_LOCKOUT_DURATION_MINUTES: getEnvNumber("ACCOUNT_LOCKOUT_DURATION_MINUTES", 30),
	PASSWORD_RESET_TOKEN_EXPIRES_HOURS: getEnvNumber("PASSWORD_RESET_TOKEN_EXPIRES_HOURS", 1),
	EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS: getEnvNumber("EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS", 24),
	SMTP_HOST: getEnvOptional("SMTP_HOST"),
	SMTP_PORT: getEnvNumber("SMTP_PORT", 587),
	SMTP_USER: getEnvOptional("SMTP_USER"),
	SMTP_PASS: getEnvOptional("SMTP_PASS"),
	SMTP_FROM: getEnvOptional("SMTP_FROM", "noreply@example.com"),
	SMTP_SECURE: getEnvBoolean("SMTP_SECURE", false)
};

//#endregion
//#region src/config/database.ts
let _prisma;
function getPrisma() {
	if (!_prisma) _prisma = new PrismaClient({
		adapter: new PrismaPg(new pg.Pool({ connectionString: env.DATABASE_URL })),
		log: ["error"]
	});
	return _prisma;
}
const prisma = new Proxy({}, { get(_, prop) {
	return getPrisma()[prop];
} });

//#endregion
//#region src/utils/crypto.ts
/**
* Generate API Key
*/
function generateApiKey() {
	const key = `${env.API_KEY_PREFIX}${nanoid(env.API_KEY_LENGTH)}`;
	return {
		key,
		prefix: key.substring(0, 8)
	};
}
/**
* Hash password
*/
async function hashPassword(password) {
	return bcrypt.hash(password, 12);
}
/**
* Compare password with hash
*/
async function comparePassword(password, hash) {
	return bcrypt.compare(password, hash);
}
/**
* Generate session token
*/
function generateSessionToken() {
	return nanoid(64);
}

//#endregion
//#region src/utils/errors.ts
var AppError = class extends Error {
	statusCode;
	code;
	isOperational;
	constructor(message, statusCode = 500, code = "INTERNAL_ERROR") {
		super(message);
		this.statusCode = statusCode;
		this.code = code;
		this.isOperational = true;
		Error.captureStackTrace(this, this.constructor);
	}
};
var NotFoundError = class extends AppError {
	constructor(resource = "Resource") {
		super(`${resource} not found`, 404, "NOT_FOUND");
	}
};
var UnauthorizedError = class extends AppError {
	constructor(message = "Unauthorized") {
		super(message, 401, "UNAUTHORIZED");
	}
};
var ForbiddenError = class extends AppError {
	constructor(message = "Forbidden") {
		super(message, 403, "FORBIDDEN");
	}
};
var BadRequestError = class extends AppError {
	constructor(message = "Bad request") {
		super(message, 400, "BAD_REQUEST");
	}
};
var ValidationError = class extends AppError {
	errors;
	constructor(errors) {
		super("Validation failed", 422, "VALIDATION_ERROR");
		this.errors = errors;
	}
};
var ConflictError = class extends AppError {
	constructor(message = "Resource already exists") {
		super(message, 409, "CONFLICT");
	}
};
function formatErrorResponse(error) {
	if (error instanceof ValidationError) return {
		success: false,
		error: error.message,
		code: error.code,
		details: error.errors
	};
	if (error instanceof AppError) return {
		success: false,
		error: error.message,
		code: error.code
	};
	console.error("Unexpected error:", error);
	return {
		success: false,
		error: "An unexpected error occurred",
		code: "INTERNAL_ERROR"
	};
}
function getErrorStatusCode(error) {
	if (error instanceof AppError) return error.statusCode;
	return 500;
}

//#endregion
//#region src/services/audit.service.ts
/**
* Create an audit log entry
* This function is non-blocking and will not throw errors to avoid disrupting the main flow
*/
async function createAuditLog(data) {
	try {
		await prisma.auditLog.create({ data: {
			userId: data.userId,
			apiKeyId: data.apiKeyId,
			action: data.action,
			entity: data.entity,
			entityId: data.entityId,
			metadata: data.metadata,
			ipAddress: data.ipAddress,
			userAgent: data.userAgent
		} });
	} catch (err) {
		console.error("[AuditLog] Failed to create log:", err);
	}
}

//#endregion
//#region src/services/email.service.ts
let transporter = null;
function getSenderEmail() {
	if (env.SMTP_HOST === "smtp.gmail.com") return env.SMTP_USER || env.SMTP_FROM || "noreply@example.com";
	return env.SMTP_FROM || env.SMTP_USER || "noreply@example.com";
}
function getTransporter() {
	if (transporter) return transporter;
	if (!env.SMTP_HOST || !env.SMTP_USER || !env.SMTP_PASS) return null;
	const isGmail = env.SMTP_HOST === "smtp.gmail.com";
	transporter = nodemailer.createTransport({
		host: env.SMTP_HOST,
		port: env.SMTP_PORT,
		secure: env.SMTP_SECURE,
		auth: {
			user: env.SMTP_USER,
			pass: env.SMTP_PASS
		},
		pool: true,
		maxConnections: 5,
		maxMessages: 100,
		...isGmail && {
			connectionTimeout: 1e4,
			greetingTimeout: 1e4,
			socketTimeout: 15e3
		},
		tls: {
			rejectUnauthorized: true,
			minVersion: "TLSv1.2"
		}
	});
	transporter.verify((error) => {
		if (error) console.error("[Email Service] SMTP connection failed:", error.message);
		else console.log("[Email Service] SMTP server is ready to send emails");
	});
	return transporter;
}
/**
* Generate a unique Message-ID for email tracking
*/
function generateMessageId() {
	const domain = getSenderEmail().split("@")[1] || "foodqueue.local";
	return `<${randomUUID()}@${domain}>`;
}
/**
* Send an email
* In development without SMTP config, logs to console instead
* Includes anti-spam headers for better deliverability
*/
async function sendEmail(options) {
	const transport = getTransporter();
	const senderEmail = getSenderEmail();
	const senderName = "Food Queue Reservation";
	if (!transport) {
		console.log("\n[Email Service - No SMTP Configured]");
		console.log(`To: ${options.to}`);
		console.log(`Subject: ${options.subject}`);
		console.log(`Body:\n${options.text || options.html}\n`);
		return true;
	}
	try {
		const messageId = generateMessageId();
		await transport.sendMail({
			from: `"${senderName}" <${senderEmail}>`,
			to: options.to,
			subject: options.subject,
			html: options.html,
			text: options.text,
			messageId,
			headers: {
				"Precedence": "bulk",
				"Auto-Submitted": "auto-generated",
				"X-Mailer": "Food Queue Reservation System",
				"List-Unsubscribe": `<mailto:${senderEmail}?subject=unsubscribe>`
			},
			replyTo: senderEmail
		});
		console.log(`[Email Service] Email sent successfully to ${options.to}`);
		return true;
	} catch (error) {
		console.error("[Email Service] Failed to send email:", error);
		return false;
	}
}
/**
* Send email verification link
*/
async function sendVerificationEmail(email, name, token) {
	const verifyUrl = `${env.FRONTEND_URL}/verify-email?token=${token}`;
	const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
	return sendEmail({
		to: email,
		subject: "ยืนยันอีเมลของคุณ - ระบบจองคิวอาหาร",
		html: `
      <!DOCTYPE html>
      <html lang="th">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <title>ยืนยันอีเมล</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4;">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #f97316, #ea580c); padding: 40px 30px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">🍜 ระบบจองคิวอาหาร</h1>
                    <p style="margin: 10px 0 0; color: rgba(255,255,255,0.9); font-size: 16px;">ยินดีต้อนรับสู่ระบบ!</p>
                  </td>
                </tr>
                <!-- Content -->
                <tr>
                  <td style="padding: 40px 30px;">
                    <h2 style="margin: 0 0 20px; color: #1f2937; font-size: 22px;">สวัสดีคุณ ${name} 👋</h2>
                    <p style="margin: 0 0 20px; color: #4b5563; font-size: 16px;">ขอบคุณที่ลงทะเบียนกับเรา! กรุณายืนยันอีเมลของคุณโดยคลิกปุ่มด้านล่าง:</p>

                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td align="center" style="padding: 30px 0;">
                          <a href="${verifyUrl}" style="display: inline-block; background: linear-gradient(135deg, #f97316, #ea580c); color: #ffffff; padding: 16px 40px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 14px rgba(249,115,22,0.4);">✓ ยืนยันอีเมล</a>
                        </td>
                      </tr>
                    </table>

                    <p style="margin: 20px 0 10px; color: #6b7280; font-size: 14px;">หรือคัดลอกลิงก์นี้ไปวางในเบราว์เซอร์:</p>
                    <p style="margin: 0 0 20px; padding: 12px; background-color: #f3f4f6; border-radius: 6px; word-break: break-all; font-size: 13px; color: #4b5563;">${verifyUrl}</p>

                    <div style="margin: 25px 0; padding: 15px; background-color: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 4px;">
                      <p style="margin: 0; color: #92400e; font-size: 14px;">⏰ ลิงก์นี้จะหมดอายุใน ${env.EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS} ชั่วโมง</p>
                    </div>

                    <p style="margin: 0; color: #9ca3af; font-size: 13px;">หากคุณไม่ได้สร้างบัญชีนี้ สามารถเพิกเฉยอีเมลนี้ได้อย่างปลอดภัย</p>
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding: 30px; background-color: #f9fafb; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0 0 10px; color: #6b7280; font-size: 14px;">ระบบจองคิวอาหาร - Food Queue Reservation</p>
                    <p style="margin: 0; color: #9ca3af; font-size: 12px;">© ${currentYear} สงวนลิขสิทธิ์</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
		text: `สวัสดีคุณ ${name},\n\nขอบคุณที่ลงทะเบียนกับระบบจองคิวอาหาร!\n\nกรุณายืนยันอีเมลของคุณโดยคลิกลิงก์:\n${verifyUrl}\n\nลิงก์นี้จะหมดอายุใน ${env.EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS} ชั่วโมง\n\nหากคุณไม่ได้สร้างบัญชีนี้ กรุณาเพิกเฉยอีเมลนี้\n\n---\nระบบจองคิวอาหาร`
	});
}
/**
* Send password reset link
*/
async function sendPasswordResetEmail(email, name, token) {
	const resetUrl = `${env.FRONTEND_URL}/reset-password?token=${token}`;
	const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
	return sendEmail({
		to: email,
		subject: "รีเซ็ตรหัสผ่าน - ระบบจองคิวอาหาร",
		html: `
      <!DOCTYPE html>
      <html lang="th">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <title>รีเซ็ตรหัสผ่าน</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4;">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #f97316, #ea580c); padding: 40px 30px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">🔐 รีเซ็ตรหัสผ่าน</h1>
                    <p style="margin: 10px 0 0; color: rgba(255,255,255,0.9); font-size: 16px;">ระบบจองคิวอาหาร</p>
                  </td>
                </tr>
                <!-- Content -->
                <tr>
                  <td style="padding: 40px 30px;">
                    <h2 style="margin: 0 0 20px; color: #1f2937; font-size: 22px;">สวัสดีคุณ ${name}</h2>
                    <p style="margin: 0 0 20px; color: #4b5563; font-size: 16px;">เราได้รับคำขอรีเซ็ตรหัสผ่านของคุณ คลิกปุ่มด้านล่างเพื่อสร้างรหัสผ่านใหม่:</p>

                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                      <tr>
                        <td align="center" style="padding: 30px 0;">
                          <a href="${resetUrl}" style="display: inline-block; background: linear-gradient(135deg, #f97316, #ea580c); color: #ffffff; padding: 16px 40px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 14px rgba(249,115,22,0.4);">🔑 รีเซ็ตรหัสผ่าน</a>
                        </td>
                      </tr>
                    </table>

                    <p style="margin: 20px 0 10px; color: #6b7280; font-size: 14px;">หรือคัดลอกลิงก์นี้ไปวางในเบราว์เซอร์:</p>
                    <p style="margin: 0 0 20px; padding: 12px; background-color: #f3f4f6; border-radius: 6px; word-break: break-all; font-size: 13px; color: #4b5563;">${resetUrl}</p>

                    <div style="margin: 25px 0; padding: 15px; background-color: #fef3c7; border-left: 4px solid #f59e0b; border-radius: 4px;">
                      <p style="margin: 0; color: #92400e; font-size: 14px;">⏰ ลิงก์นี้จะหมดอายุใน ${env.PASSWORD_RESET_TOKEN_EXPIRES_HOURS} ชั่วโมง</p>
                    </div>

                    <div style="margin: 25px 0; padding: 15px; background-color: #fef2f2; border-left: 4px solid #ef4444; border-radius: 4px;">
                      <p style="margin: 0; color: #991b1b; font-size: 14px;"><strong>⚠️ คำเตือนด้านความปลอดภัย:</strong> หากคุณไม่ได้ขอรีเซ็ตรหัสผ่าน กรุณาเพิกเฉยอีเมลนี้ รหัสผ่านของคุณจะยังคงเหมือนเดิม</p>
                    </div>
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding: 30px; background-color: #f9fafb; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0 0 10px; color: #6b7280; font-size: 14px;">ระบบจองคิวอาหาร - Food Queue Reservation</p>
                    <p style="margin: 0; color: #9ca3af; font-size: 12px;">© ${currentYear} สงวนลิขสิทธิ์</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
		text: `สวัสดีคุณ ${name},\n\nเราได้รับคำขอรีเซ็ตรหัสผ่านของคุณ\n\nคลิกลิงก์นี้เพื่อสร้างรหัสผ่านใหม่:\n${resetUrl}\n\nลิงก์นี้จะหมดอายุใน ${env.PASSWORD_RESET_TOKEN_EXPIRES_HOURS} ชั่วโมง\n\nหากคุณไม่ได้ขอรีเซ็ตรหัสผ่าน กรุณาเพิกเฉยอีเมลนี้\n\n---\nระบบจองคิวอาหาร`
	});
}
/**
* Send account locked notification
*/
/**
* Send a test email to verify SMTP configuration
*/
async function sendTestEmail(email) {
	const transport = getTransporter();
	const senderEmail = getSenderEmail();
	const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
	if (!transport) return {
		success: false,
		message: "SMTP not configured. Please set SMTP_HOST, SMTP_USER, and SMTP_PASS in .env file."
	};
	try {
		const result = await transport.sendMail({
			from: `"Food Queue Reservation" <${senderEmail}>`,
			to: email,
			subject: "✅ ทดสอบระบบอีเมล - ระบบจองคิวอาหาร",
			messageId: generateMessageId(),
			headers: {
				"Precedence": "bulk",
				"Auto-Submitted": "auto-generated",
				"X-Mailer": "Food Queue Reservation System"
			},
			replyTo: senderEmail,
			html: `
        <!DOCTYPE html>
        <html lang="th">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>ทดสอบอีเมล</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f4f4f4;">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4;">
            <tr>
              <td align="center" style="padding: 40px 20px;">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                  <tr>
                    <td style="background: linear-gradient(135deg, #22c55e, #16a34a); padding: 40px 30px; text-align: center;">
                      <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">✅ ทดสอบสำเร็จ!</h1>
                      <p style="margin: 10px 0 0; color: rgba(255,255,255,0.9); font-size: 16px;">ระบบอีเมลทำงานปกติ</p>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding: 40px 30px; text-align: center;">
                      <p style="margin: 0 0 20px; color: #4b5563; font-size: 16px;">อีเมลนี้ถูกส่งเพื่อทดสอบการตั้งค่า SMTP</p>
                      <p style="margin: 0 0 20px; color: #4b5563; font-size: 14px;">ส่งจาก: <strong>${senderEmail}</strong></p>
                      <p style="margin: 0 0 20px; color: #4b5563; font-size: 14px;">เวลา: <strong>${(/* @__PURE__ */ new Date()).toLocaleString("th-TH", { timeZone: "Asia/Bangkok" })}</strong></p>
                      <div style="margin: 25px 0; padding: 15px; background-color: #dcfce7; border-left: 4px solid #22c55e; border-radius: 4px;">
                        <p style="margin: 0; color: #166534; font-size: 14px;">🎉 ระบบอีเมลของคุณพร้อมใช้งานแล้ว!</p>
                      </div>
                    </td>
                  </tr>
                  <tr>
                    <td style="padding: 30px; background-color: #f9fafb; text-align: center; border-top: 1px solid #e5e7eb;">
                      <p style="margin: 0; color: #9ca3af; font-size: 12px;">© ${currentYear} ระบบจองคิวอาหาร</p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
      `,
			text: `ทดสอบระบบอีเมลสำเร็จ!\n\nอีเมลนี้ถูกส่งเพื่อทดสอบการตั้งค่า SMTP\nส่งจาก: ${senderEmail}\nเวลา: ${(/* @__PURE__ */ new Date()).toLocaleString("th-TH", { timeZone: "Asia/Bangkok" })}\n\nระบบอีเมลของคุณพร้อมใช้งานแล้ว!`
		});
		console.log("[Email Service] Test email sent successfully:", result.messageId);
		return {
			success: true,
			message: `Test email sent successfully to ${email}. Message ID: ${result.messageId}`
		};
	} catch (error) {
		console.error("[Email Service] Test email failed:", error);
		return {
			success: false,
			message: `Failed to send test email: ${error.message || "Unknown error"}`
		};
	}
}
/**
* Generate order items table HTML
*/
function generateOrderItemsHtml(items) {
	return items.map((item) => `
    <tr>
      <td style="padding: 10px 15px; border-bottom: 1px solid #e5e7eb;">${item.name}</td>
      <td style="padding: 10px 15px; border-bottom: 1px solid #e5e7eb; text-align: center;">${item.quantity}</td>
      <td style="padding: 10px 15px; border-bottom: 1px solid #e5e7eb; text-align: right;">฿${(item.price * item.quantity).toLocaleString()}</td>
    </tr>
  `).join("");
}
/**
* Send order confirmed email
*/
async function sendOrderConfirmedEmail(email, order) {
	const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
	return sendEmail({
		to: email,
		subject: `✅ ยืนยันคำสั่งซื้อ #${order.queueNumber} - ${order.vendorName}`,
		html: `
      <!DOCTYPE html>
      <html lang="th">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ยืนยันคำสั่งซื้อ</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4;">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #22c55e, #16a34a); padding: 40px 30px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">✅ ยืนยันคำสั่งซื้อแล้ว!</h1>
                    <p style="margin: 10px 0 0; color: rgba(255,255,255,0.9); font-size: 16px;">${order.vendorName}</p>
                  </td>
                </tr>
                <!-- Queue Number -->
                <tr>
                  <td style="padding: 30px; text-align: center; background-color: #f0fdf4;">
                    <p style="margin: 0 0 5px; color: #166534; font-size: 14px;">หมายเลขคิวของคุณ</p>
                    <p style="margin: 0; color: #166534; font-size: 48px; font-weight: bold;">#${order.queueNumber}</p>
                  </td>
                </tr>
                <!-- Content -->
                <tr>
                  <td style="padding: 30px;">
                    <h2 style="margin: 0 0 20px; color: #1f2937; font-size: 18px;">สวัสดีคุณ ${order.customerName}</h2>
                    <p style="margin: 0 0 20px; color: #4b5563; font-size: 16px;">ร้านค้าได้รับคำสั่งซื้อของคุณแล้ว กรุณารอการเตรียมอาหาร</p>

                    ${order.timeSlot ? `
                    <div style="margin: 0 0 20px; padding: 15px; background-color: #fef3c7; border-radius: 8px;">
                      <p style="margin: 0; color: #92400e; font-size: 14px;">⏰ ช่วงเวลารับอาหาร: <strong>${order.timeSlot}</strong></p>
                    </div>
                    ` : ""}

                    <!-- Order Items -->
                    <h3 style="margin: 20px 0 15px; color: #1f2937; font-size: 16px;">รายการอาหาร</h3>
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f9fafb; border-radius: 8px; overflow: hidden;">
                      <tr style="background-color: #f3f4f6;">
                        <th style="padding: 12px 15px; text-align: left; font-size: 14px; color: #4b5563;">รายการ</th>
                        <th style="padding: 12px 15px; text-align: center; font-size: 14px; color: #4b5563;">จำนวน</th>
                        <th style="padding: 12px 15px; text-align: right; font-size: 14px; color: #4b5563;">ราคา</th>
                      </tr>
                      ${generateOrderItemsHtml(order.items)}
                      <tr style="background-color: #f3f4f6;">
                        <td colspan="2" style="padding: 12px 15px; font-weight: bold; color: #1f2937;">รวมทั้งหมด</td>
                        <td style="padding: 12px 15px; text-align: right; font-weight: bold; color: #f97316; font-size: 18px;">฿${order.totalAmount.toLocaleString()}</td>
                      </tr>
                    </table>

                    <div style="margin: 25px 0; padding: 15px; background-color: #dbeafe; border-left: 4px solid #3b82f6; border-radius: 4px;">
                      <p style="margin: 0; color: #1e40af; font-size: 14px;">📱 คุณจะได้รับอีเมลแจ้งเตือนเมื่อออเดอร์พร้อมรับ</p>
                    </div>
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding: 30px; background-color: #f9fafb; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0 0 10px; color: #6b7280; font-size: 14px;">ระบบจองคิวอาหาร - Food Queue Reservation</p>
                    <p style="margin: 0; color: #9ca3af; font-size: 12px;">© ${currentYear} สงวนลิขสิทธิ์</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
		text: `ยืนยันคำสั่งซื้อแล้ว!\n\nหมายเลขคิว: #${order.queueNumber}\nร้าน: ${order.vendorName}\n${order.timeSlot ? `ช่วงเวลารับ: ${order.timeSlot}\n` : ""}\nรวมทั้งหมด: ฿${order.totalAmount.toLocaleString()}\n\nกรุณารอการเตรียมอาหาร`
	});
}
/**
* Send order preparing email
*/
async function sendOrderPreparingEmail(email, order) {
	const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
	return sendEmail({
		to: email,
		subject: `🍳 กำลังเตรียมออเดอร์ #${order.queueNumber} - ${order.vendorName}`,
		html: `
      <!DOCTYPE html>
      <html lang="th">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>กำลังเตรียมออเดอร์</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4;">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #f97316, #ea580c); padding: 40px 30px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">🍳 กำลังเตรียมอาหาร</h1>
                    <p style="margin: 10px 0 0; color: rgba(255,255,255,0.9); font-size: 16px;">${order.vendorName}</p>
                  </td>
                </tr>
                <!-- Queue Number -->
                <tr>
                  <td style="padding: 30px; text-align: center; background-color: #fff7ed;">
                    <p style="margin: 0 0 5px; color: #c2410c; font-size: 14px;">หมายเลขคิว</p>
                    <p style="margin: 0; color: #c2410c; font-size: 48px; font-weight: bold;">#${order.queueNumber}</p>
                  </td>
                </tr>
                <!-- Content -->
                <tr>
                  <td style="padding: 30px;">
                    <h2 style="margin: 0 0 20px; color: #1f2937; font-size: 18px;">สวัสดีคุณ ${order.customerName}</h2>
                    <p style="margin: 0 0 20px; color: #4b5563; font-size: 16px;">ร้านค้าเริ่มเตรียมออเดอร์ของคุณแล้ว กรุณารอสักครู่</p>

                    <div style="margin: 20px 0; padding: 20px; background-color: #fef3c7; border-radius: 8px; text-align: center;">
                      <p style="margin: 0; color: #92400e; font-size: 16px;">⏱️ <strong>อาหารกำลังจัดเตรียม...</strong></p>
                      <p style="margin: 10px 0 0; color: #a16207; font-size: 14px;">คุณจะได้รับแจ้งเตือนเมื่อพร้อมรับ</p>
                    </div>

                    <!-- Order Items -->
                    <h3 style="margin: 20px 0 15px; color: #1f2937; font-size: 16px;">รายการที่กำลังเตรียม</h3>
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f9fafb; border-radius: 8px; overflow: hidden;">
                      <tr style="background-color: #f3f4f6;">
                        <th style="padding: 12px 15px; text-align: left; font-size: 14px; color: #4b5563;">รายการ</th>
                        <th style="padding: 12px 15px; text-align: center; font-size: 14px; color: #4b5563;">จำนวน</th>
                        <th style="padding: 12px 15px; text-align: right; font-size: 14px; color: #4b5563;">ราคา</th>
                      </tr>
                      ${generateOrderItemsHtml(order.items)}
                    </table>
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding: 30px; background-color: #f9fafb; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0 0 10px; color: #6b7280; font-size: 14px;">ระบบจองคิวอาหาร - Food Queue Reservation</p>
                    <p style="margin: 0; color: #9ca3af; font-size: 12px;">© ${currentYear} สงวนลิขสิทธิ์</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
		text: `กำลังเตรียมอาหาร!\n\nหมายเลขคิว: #${order.queueNumber}\nร้าน: ${order.vendorName}\n\nร้านค้าเริ่มเตรียมออเดอร์ของคุณแล้ว คุณจะได้รับแจ้งเตือนเมื่อพร้อมรับ`
	});
}
/**
* Send order ready email
*/
async function sendOrderReadyEmail(email, order) {
	const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
	return sendEmail({
		to: email,
		subject: `🎉 ออเดอร์ #${order.queueNumber} พร้อมรับแล้ว! - ${order.vendorName}`,
		html: `
      <!DOCTYPE html>
      <html lang="th">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ออเดอร์พร้อมรับแล้ว</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4;">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #10b981, #059669); padding: 40px 30px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">🎉 พร้อมรับแล้ว!</h1>
                    <p style="margin: 10px 0 0; color: rgba(255,255,255,0.9); font-size: 16px;">${order.vendorName}</p>
                  </td>
                </tr>
                <!-- Queue Number -->
                <tr>
                  <td style="padding: 30px; text-align: center; background-color: #ecfdf5;">
                    <p style="margin: 0 0 5px; color: #047857; font-size: 14px;">หมายเลขคิว</p>
                    <p style="margin: 0; color: #047857; font-size: 56px; font-weight: bold;">#${order.queueNumber}</p>
                  </td>
                </tr>
                <!-- Content -->
                <tr>
                  <td style="padding: 30px;">
                    <h2 style="margin: 0 0 20px; color: #1f2937; font-size: 18px;">สวัสดีคุณ ${order.customerName}</h2>

                    <div style="margin: 0 0 25px; padding: 20px; background-color: #dcfce7; border: 2px solid #22c55e; border-radius: 8px; text-align: center;">
                      <p style="margin: 0; color: #166534; font-size: 20px; font-weight: bold;">🔔 อาหารของคุณพร้อมแล้ว!</p>
                      <p style="margin: 10px 0 0; color: #15803d; font-size: 16px;">กรุณามารับที่ร้าน <strong>${order.vendorName}</strong></p>
                    </div>

                    <p style="margin: 0 0 20px; color: #4b5563; font-size: 16px;">แสดงหมายเลขคิว <strong>#${order.queueNumber}</strong> ที่ร้านเพื่อรับอาหาร</p>

                    <!-- Order Items -->
                    <h3 style="margin: 20px 0 15px; color: #1f2937; font-size: 16px;">รายการของคุณ</h3>
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f9fafb; border-radius: 8px; overflow: hidden;">
                      <tr style="background-color: #f3f4f6;">
                        <th style="padding: 12px 15px; text-align: left; font-size: 14px; color: #4b5563;">รายการ</th>
                        <th style="padding: 12px 15px; text-align: center; font-size: 14px; color: #4b5563;">จำนวน</th>
                        <th style="padding: 12px 15px; text-align: right; font-size: 14px; color: #4b5563;">ราคา</th>
                      </tr>
                      ${generateOrderItemsHtml(order.items)}
                      <tr style="background-color: #f3f4f6;">
                        <td colspan="2" style="padding: 12px 15px; font-weight: bold; color: #1f2937;">รวมทั้งหมด</td>
                        <td style="padding: 12px 15px; text-align: right; font-weight: bold; color: #f97316; font-size: 18px;">฿${order.totalAmount.toLocaleString()}</td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding: 30px; background-color: #f9fafb; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0 0 10px; color: #6b7280; font-size: 14px;">ระบบจองคิวอาหาร - Food Queue Reservation</p>
                    <p style="margin: 0; color: #9ca3af; font-size: 12px;">© ${currentYear} สงวนลิขสิทธิ์</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
		text: `🎉 ออเดอร์พร้อมรับแล้ว!\n\nหมายเลขคิว: #${order.queueNumber}\nร้าน: ${order.vendorName}\n\nอาหารของคุณพร้อมแล้ว! กรุณามารับที่ร้าน\nแสดงหมายเลขคิว #${order.queueNumber} เพื่อรับอาหาร`
	});
}
/**
* Send order completed email with review reminder
*/
async function sendOrderCompletedEmail(email, order, reviewUrl) {
	const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
	const defaultReviewUrl = `${env.FRONTEND_URL}/reviews`;
	return sendEmail({
		to: email,
		subject: `🙏 ขอบคุณที่ใช้บริการ - ร้าน ${order.vendorName}`,
		html: `
      <!DOCTYPE html>
      <html lang="th">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ขอบคุณที่ใช้บริการ</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4;">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #8b5cf6, #7c3aed); padding: 40px 30px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">🙏 ขอบคุณที่ใช้บริการ!</h1>
                    <p style="margin: 10px 0 0; color: rgba(255,255,255,0.9); font-size: 16px;">${order.vendorName}</p>
                  </td>
                </tr>
                <!-- Content -->
                <tr>
                  <td style="padding: 30px;">
                    <h2 style="margin: 0 0 20px; color: #1f2937; font-size: 18px;">สวัสดีคุณ ${order.customerName}</h2>
                    <p style="margin: 0 0 20px; color: #4b5563; font-size: 16px;">ออเดอร์ #${order.queueNumber} ของคุณเสร็จสมบูรณ์แล้ว ขอบคุณที่ใช้บริการ!</p>

                    <!-- Order Summary -->
                    <div style="margin: 0 0 25px; padding: 20px; background-color: #f3f4f6; border-radius: 8px;">
                      <p style="margin: 0 0 10px; color: #4b5563; font-size: 14px;">สรุปคำสั่งซื้อ</p>
                      <p style="margin: 0; color: #1f2937; font-size: 24px; font-weight: bold;">฿${order.totalAmount.toLocaleString()}</p>
                    </div>

                    <!-- Review CTA -->
                    <div style="margin: 25px 0; padding: 25px; background: linear-gradient(135deg, #fef3c7, #fde68a); border-radius: 12px; text-align: center;">
                      <p style="margin: 0 0 15px; color: #92400e; font-size: 18px; font-weight: bold;">⭐ รีวิวร้านค้า</p>
                      <p style="margin: 0 0 20px; color: #a16207; font-size: 14px;">แชร์ประสบการณ์ของคุณเพื่อช่วยเหลือผู้ใช้คนอื่น</p>
                      <a href="${reviewUrl || defaultReviewUrl}" style="display: inline-block; background: linear-gradient(135deg, #f97316, #ea580c); color: #ffffff; padding: 14px 35px; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px; box-shadow: 0 4px 14px rgba(249,115,22,0.4);">✍️ เขียนรีวิว</a>
                    </div>

                    <p style="margin: 0; color: #9ca3af; font-size: 13px; text-align: center;">หวังว่าจะได้พบคุณอีกครั้ง!</p>
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding: 30px; background-color: #f9fafb; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0 0 10px; color: #6b7280; font-size: 14px;">ระบบจองคิวอาหาร - Food Queue Reservation</p>
                    <p style="margin: 0; color: #9ca3af; font-size: 12px;">© ${currentYear} สงวนลิขสิทธิ์</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
		text: `🙏 ขอบคุณที่ใช้บริการ!\n\nร้าน: ${order.vendorName}\nออเดอร์: #${order.queueNumber}\nยอดรวม: ฿${order.totalAmount.toLocaleString()}\n\n⭐ รีวิวร้านค้า: ${reviewUrl || defaultReviewUrl}\n\nหวังว่าจะได้พบคุณอีกครั้ง!`
	});
}
/**
* Send order cancelled email
*/
async function sendOrderCancelledEmail(email, order, reason) {
	const currentYear = (/* @__PURE__ */ new Date()).getFullYear();
	return sendEmail({
		to: email,
		subject: `❌ ยกเลิกคำสั่งซื้อ #${order.queueNumber} - ${order.vendorName}`,
		html: `
      <!DOCTYPE html>
      <html lang="th">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>ยกเลิกคำสั่งซื้อ</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4;">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #ef4444, #dc2626); padding: 40px 30px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">❌ คำสั่งซื้อถูกยกเลิก</h1>
                    <p style="margin: 10px 0 0; color: rgba(255,255,255,0.9); font-size: 16px;">${order.vendorName}</p>
                  </td>
                </tr>
                <!-- Content -->
                <tr>
                  <td style="padding: 30px;">
                    <h2 style="margin: 0 0 20px; color: #1f2937; font-size: 18px;">สวัสดีคุณ ${order.customerName}</h2>
                    <p style="margin: 0 0 20px; color: #4b5563; font-size: 16px;">คำสั่งซื้อ #${order.queueNumber} ถูกยกเลิกแล้ว</p>

                    ${reason ? `
                    <div style="margin: 0 0 25px; padding: 15px; background-color: #fef2f2; border-left: 4px solid #ef4444; border-radius: 4px;">
                      <p style="margin: 0; color: #991b1b; font-size: 14px;"><strong>เหตุผล:</strong> ${reason}</p>
                    </div>
                    ` : ""}

                    <!-- Order Items -->
                    <h3 style="margin: 20px 0 15px; color: #1f2937; font-size: 16px;">รายการที่ถูกยกเลิก</h3>
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f9fafb; border-radius: 8px; overflow: hidden; opacity: 0.7;">
                      <tr style="background-color: #f3f4f6;">
                        <th style="padding: 12px 15px; text-align: left; font-size: 14px; color: #4b5563;">รายการ</th>
                        <th style="padding: 12px 15px; text-align: center; font-size: 14px; color: #4b5563;">จำนวน</th>
                        <th style="padding: 12px 15px; text-align: right; font-size: 14px; color: #4b5563;">ราคา</th>
                      </tr>
                      ${generateOrderItemsHtml(order.items)}
                      <tr style="background-color: #f3f4f6;">
                        <td colspan="2" style="padding: 12px 15px; font-weight: bold; color: #1f2937; text-decoration: line-through;">รวมทั้งหมด</td>
                        <td style="padding: 12px 15px; text-align: right; font-weight: bold; color: #9ca3af; font-size: 18px; text-decoration: line-through;">฿${order.totalAmount.toLocaleString()}</td>
                      </tr>
                    </table>

                    <p style="margin: 25px 0 0; color: #6b7280; font-size: 14px; text-align: center;">หากมีข้อสงสัยกรุณาติดต่อร้านค้าโดยตรง</p>
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding: 30px; background-color: #f9fafb; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0 0 10px; color: #6b7280; font-size: 14px;">ระบบจองคิวอาหาร - Food Queue Reservation</p>
                    <p style="margin: 0; color: #9ca3af; font-size: 12px;">© ${currentYear} สงวนลิขสิทธิ์</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
		text: `❌ คำสั่งซื้อถูกยกเลิก\n\nหมายเลขคิว: #${order.queueNumber}\nร้าน: ${order.vendorName}\n${reason ? `เหตุผล: ${reason}\n` : ""}\nยอดที่ถูกยกเลิก: ฿${order.totalAmount.toLocaleString()}`
	});
}
async function sendAccountLockedEmail(email, name, lockedUntil) {
	const unlockTime = lockedUntil.toLocaleString("th-TH", {
		timeZone: "Asia/Bangkok",
		dateStyle: "medium",
		timeStyle: "short"
	});
	return sendEmail({
		to: email,
		subject: "🚨 แจ้งเตือนความปลอดภัย - บัญชีถูกล็อคชั่วคราว",
		html: `
      <!DOCTYPE html>
      <html lang="th">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <title>แจ้งเตือนความปลอดภัย</title>
      </head>
      <body style="margin: 0; padding: 0; font-family: 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333333; background-color: #f4f4f4;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color: #f4f4f4;">
          <tr>
            <td align="center" style="padding: 40px 20px;">
              <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                <!-- Header -->
                <tr>
                  <td style="background: linear-gradient(135deg, #dc2626, #b91c1c); padding: 40px 30px; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 28px; font-weight: bold;">🚨 แจ้งเตือนความปลอดภัย</h1>
                    <p style="margin: 10px 0 0; color: rgba(255,255,255,0.9); font-size: 16px;">บัญชีของคุณถูกล็อคชั่วคราว</p>
                  </td>
                </tr>
                <!-- Content -->
                <tr>
                  <td style="padding: 40px 30px;">
                    <h2 style="margin: 0 0 20px; color: #1f2937; font-size: 22px;">สวัสดีคุณ ${name}</h2>

                    <div style="margin: 0 0 25px; padding: 20px; background-color: #fef2f2; border: 1px solid #fecaca; border-radius: 8px;">
                      <p style="margin: 0; color: #991b1b; font-size: 16px; font-weight: bold;">⚠️ บัญชีของคุณถูกล็อคชั่วคราว</p>
                      <p style="margin: 10px 0 0; color: #7f1d1d; font-size: 14px;">เนื่องจากมีการพยายามเข้าสู่ระบบด้วยรหัสผ่านผิดหลายครั้ง</p>
                    </div>

                    <p style="margin: 0 0 20px; color: #4b5563; font-size: 16px;">บัญชีของคุณจะถูกปลดล็อคอัตโนมัติในเวลา:</p>
                    <p style="margin: 0 0 25px; padding: 15px; background-color: #f3f4f6; border-radius: 8px; text-align: center; font-size: 18px; font-weight: bold; color: #1f2937;">${unlockTime}</p>

                    <p style="margin: 0 0 15px; color: #4b5563; font-size: 16px;">หากไม่ใช่คุณที่พยายามเข้าสู่ระบบ เราแนะนำให้:</p>
                    <ul style="margin: 0 0 25px; padding-left: 20px; color: #4b5563;">
                      <li style="margin-bottom: 8px;">รีเซ็ตรหัสผ่านทันทีหลังจากบัญชีถูกปลดล็อค</li>
                      <li style="margin-bottom: 8px;">ใช้รหัสผ่านที่แข็งแกร่งและไม่ซ้ำกับที่อื่น</li>
                      <li style="margin-bottom: 8px;">ตรวจสอบกิจกรรมที่น่าสงสัยในบัญชีของคุณ</li>
                    </ul>

                    <p style="margin: 0; color: #9ca3af; font-size: 13px;">หากคุณมีคำถาม กรุณาติดต่อทีมสนับสนุนของเรา</p>
                  </td>
                </tr>
                <!-- Footer -->
                <tr>
                  <td style="padding: 30px; background-color: #f9fafb; text-align: center; border-top: 1px solid #e5e7eb;">
                    <p style="margin: 0 0 10px; color: #6b7280; font-size: 14px;">ระบบจองคิวอาหาร - Food Queue Reservation</p>
                    <p style="margin: 0; color: #9ca3af; font-size: 12px;">© ${(/* @__PURE__ */ new Date()).getFullYear()} สงวนลิขสิทธิ์</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `,
		text: `สวัสดีคุณ ${name},\n\n⚠️ บัญชีของคุณถูกล็อคชั่วคราว\n\nเนื่องจากมีการพยายามเข้าสู่ระบบด้วยรหัสผ่านผิดหลายครั้ง\n\nบัญชีของคุณจะถูกปลดล็อคอัตโนมัติในเวลา: ${unlockTime}\n\nหากไม่ใช่คุณที่พยายามเข้าสู่ระบบ กรุณารีเซ็ตรหัสผ่านทันทีหลังจากบัญชีถูกปลดล็อค\n\n---\nระบบจองคิวอาหาร`
	});
}

//#endregion
//#region src/services/auth.service.ts
function getSessionExpiry() {
	const match = env.JWT_EXPIRES_IN.match(/^(\d+)([dhms])$/);
	if (!match) return new Date(Date.now() + 10080 * 60 * 1e3);
	const value = parseInt(match[1], 10);
	const unit = match[2];
	let ms;
	switch (unit) {
		case "d":
			ms = value * 24 * 60 * 60 * 1e3;
			break;
		case "h":
			ms = value * 60 * 60 * 1e3;
			break;
		case "m":
			ms = value * 60 * 1e3;
			break;
		case "s":
			ms = value * 1e3;
			break;
		default: ms = 10080 * 60 * 1e3;
	}
	return new Date(Date.now() + ms);
}
/**
* Check if account is locked
*/
async function checkAccountLockout(user) {
	if (user.lockedUntil && user.lockedUntil > /* @__PURE__ */ new Date()) {
		const remainingMinutes = Math.ceil((user.lockedUntil.getTime() - Date.now()) / 6e4);
		await createAuditLog({
			userId: user.id,
			action: "LOGIN_BLOCKED_LOCKOUT",
			entity: "User",
			entityId: user.id,
			metadata: {
				remainingMinutes,
				email: user.email
			}
		});
		throw new UnauthorizedError(`Account is locked due to too many failed login attempts. Please try again in ${remainingMinutes} minute(s).`);
	}
}
/**
* Record a failed login attempt
*/
async function recordFailedLogin(userId, email) {
	const user = await prisma.user.update({
		where: { id: userId },
		data: {
			failedLoginAttempts: { increment: 1 },
			lastFailedLogin: /* @__PURE__ */ new Date()
		},
		select: {
			failedLoginAttempts: true,
			name: true
		}
	});
	await createAuditLog({
		userId,
		action: "LOGIN_FAILED",
		entity: "User",
		entityId: userId,
		metadata: {
			email,
			failedAttempts: user.failedLoginAttempts
		}
	});
	if (user.failedLoginAttempts >= env.ACCOUNT_LOCKOUT_THRESHOLD) {
		const lockUntil = new Date(Date.now() + env.ACCOUNT_LOCKOUT_DURATION_MINUTES * 60 * 1e3);
		await prisma.user.update({
			where: { id: userId },
			data: { lockedUntil: lockUntil }
		});
		await createAuditLog({
			userId,
			action: "ACCOUNT_LOCKED",
			entity: "User",
			entityId: userId,
			metadata: {
				failedAttempts: user.failedLoginAttempts,
				lockedUntil: lockUntil.toISOString()
			}
		});
		await sendAccountLockedEmail(email, user.name, lockUntil);
	}
}
/**
* Reset failed login attempts on successful login
*/
async function resetFailedLoginAttempts(userId) {
	await prisma.user.update({
		where: { id: userId },
		data: {
			failedLoginAttempts: 0,
			lockedUntil: null,
			lastFailedLogin: null
		}
	});
}
/**
* Register a new user
*/
async function register(input) {
	if (await prisma.user.findUnique({ where: { email: input.email } })) throw new ConflictError("User with this email already exists");
	const hashedPassword = await hashPassword(input.password);
	const user = await prisma.user.create({
		data: {
			email: input.email,
			name: input.name,
			phone: input.phone,
			password: hashedPassword,
			role: input.role,
			emailVerified: false
		},
		select: {
			id: true,
			email: true,
			name: true,
			phone: true,
			avatar: true,
			role: true,
			createdAt: true
		}
	});
	const verificationToken = await generateEmailVerificationToken(user.id);
	await sendVerificationEmail(user.email, user.name, verificationToken);
	await createAuditLog({
		userId: user.id,
		action: "REGISTER",
		entity: "User",
		entityId: user.id,
		metadata: {
			email: user.email,
			role: user.role
		}
	});
	return createSession(user);
}
/**
* Login with email and password
*/
async function login(input) {
	const user = await prisma.user.findUnique({
		where: { email: input.email },
		select: {
			id: true,
			email: true,
			name: true,
			phone: true,
			avatar: true,
			role: true,
			password: true,
			isActive: true,
			lockedUntil: true,
			failedLoginAttempts: true,
			createdAt: true
		}
	});
	if (!user) {
		await comparePassword(input.password, "$2a$12$invalidhashfortimingattak");
		throw new UnauthorizedError("Invalid email or password");
	}
	await checkAccountLockout(user);
	if (!user.password) throw new UnauthorizedError("Invalid email or password");
	if (!await comparePassword(input.password, user.password)) {
		await recordFailedLogin(user.id, user.email);
		throw new UnauthorizedError("Invalid email or password");
	}
	if (!user.isActive) throw new UnauthorizedError("Account is disabled");
	await resetFailedLoginAttempts(user.id);
	await createAuditLog({
		userId: user.id,
		action: "LOGIN_SUCCESS",
		entity: "User",
		entityId: user.id,
		metadata: { email: user.email }
	});
	return createSession({
		id: user.id,
		email: user.email,
		name: user.name,
		phone: user.phone,
		avatar: user.avatar,
		role: user.role,
		createdAt: user.createdAt
	});
}
/**
* Login/Register with Google OAuth
*/
async function googleAuth(googleUser, tokens) {
	let account = await prisma.account.findUnique({
		where: { provider_providerAccountId: {
			provider: "google",
			providerAccountId: googleUser.id
		} },
		include: { user: true }
	});
	let user;
	if (account) {
		await prisma.account.update({
			where: { id: account.id },
			data: {
				accessToken: tokens.accessToken,
				refreshToken: tokens.refreshToken,
				expiresAt: tokens.expiresAt
			}
		});
		user = {
			id: account.user.id,
			email: account.user.email,
			name: account.user.name,
			phone: account.user.phone,
			avatar: account.user.avatar,
			role: account.user.role,
			createdAt: account.user.createdAt
		};
		await createAuditLog({
			userId: user.id,
			action: "OAUTH_LOGIN",
			entity: "User",
			entityId: user.id,
			metadata: { provider: "google" }
		});
	} else {
		const existingUser = await prisma.user.findUnique({ where: { email: googleUser.email } });
		if (existingUser) {
			await prisma.account.create({ data: {
				userId: existingUser.id,
				type: "oauth",
				provider: "google",
				providerAccountId: googleUser.id,
				accessToken: tokens.accessToken,
				refreshToken: tokens.refreshToken,
				expiresAt: tokens.expiresAt
			} });
			user = {
				id: existingUser.id,
				email: existingUser.email,
				name: existingUser.name,
				phone: existingUser.phone,
				avatar: existingUser.avatar || googleUser.picture || null,
				role: existingUser.role,
				createdAt: existingUser.createdAt
			};
			if (!existingUser.avatar && googleUser.picture) await prisma.user.update({
				where: { id: existingUser.id },
				data: {
					avatar: googleUser.picture,
					emailVerified: true
				}
			});
			await createAuditLog({
				userId: user.id,
				action: "OAUTH_LINK",
				entity: "User",
				entityId: user.id,
				metadata: { provider: "google" }
			});
		} else {
			const newUser = await prisma.user.create({ data: {
				email: googleUser.email,
				name: googleUser.name,
				avatar: googleUser.picture,
				emailVerified: true,
				accounts: { create: {
					type: "oauth",
					provider: "google",
					providerAccountId: googleUser.id,
					accessToken: tokens.accessToken,
					refreshToken: tokens.refreshToken,
					expiresAt: tokens.expiresAt
				} }
			} });
			user = {
				id: newUser.id,
				email: newUser.email,
				name: newUser.name,
				phone: newUser.phone,
				avatar: newUser.avatar,
				role: newUser.role,
				createdAt: newUser.createdAt
			};
			await createAuditLog({
				userId: user.id,
				action: "REGISTER",
				entity: "User",
				entityId: user.id,
				metadata: {
					provider: "google",
					email: user.email
				}
			});
		}
	}
	return createSession(user);
}
/**
* Create a new session for user
*/
async function createSession(user) {
	const token = generateSessionToken();
	const expiresAt = getSessionExpiry();
	await prisma.session.create({ data: {
		userId: user.id,
		token,
		expiresAt
	} });
	return {
		user,
		token,
		expiresAt
	};
}
/**
* Validate session token and return user
*/
async function validateSession(token) {
	const session = await prisma.session.findUnique({
		where: { token },
		include: { user: true }
	});
	if (!session) return null;
	if (session.expiresAt < /* @__PURE__ */ new Date()) {
		await prisma.session.delete({ where: { id: session.id } });
		return null;
	}
	if (!session.user.isActive) return null;
	await prisma.session.update({
		where: { id: session.id },
		data: { lastActiveAt: /* @__PURE__ */ new Date() }
	});
	return {
		id: session.user.id,
		email: session.user.email,
		name: session.user.name,
		phone: session.user.phone,
		avatar: session.user.avatar,
		role: session.user.role,
		createdAt: session.user.createdAt
	};
}
/**
* Logout - delete session
*/
async function logout(token, userId) {
	await prisma.session.deleteMany({ where: { token } });
	if (userId) await createAuditLog({
		userId,
		action: "LOGOUT",
		entity: "User",
		entityId: userId
	});
}
/**
* Logout all sessions for a user
*/
async function logoutAll(userId) {
	await prisma.session.deleteMany({ where: { userId } });
	await createAuditLog({
		userId,
		action: "LOGOUT_ALL",
		entity: "User",
		entityId: userId
	});
}
/**
* Get user sessions
*/
async function getUserSessions(userId) {
	return prisma.session.findMany({
		where: { userId },
		select: {
			id: true,
			createdAt: true,
			lastActiveAt: true,
			userAgent: true,
			ipAddress: true
		},
		orderBy: { lastActiveAt: "desc" }
	});
}
/**
* Delete specific session
*/
async function deleteSession(userId, sessionId) {
	await prisma.session.deleteMany({ where: {
		id: sessionId,
		userId
	} });
	await createAuditLog({
		userId,
		action: "SESSION_DELETED",
		entity: "Session",
		entityId: sessionId
	});
}
/**
* Generate email verification token
*/
async function generateEmailVerificationToken(userId) {
	const token = nanoid(64);
	const expires = new Date(Date.now() + env.EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS * 60 * 60 * 1e3);
	const hashedToken = await hashPassword(token);
	await prisma.user.update({
		where: { id: userId },
		data: {
			emailVerificationToken: hashedToken,
			emailVerificationExpires: expires
		}
	});
	return token;
}
/**
* Verify email with token
*/
async function verifyEmail(token) {
	const users = await prisma.user.findMany({
		where: {
			emailVerified: false,
			emailVerificationToken: { not: null },
			emailVerificationExpires: { gt: /* @__PURE__ */ new Date() }
		},
		select: {
			id: true,
			email: true,
			emailVerificationToken: true
		}
	});
	let matchedUser = null;
	for (const user of users) if (user.emailVerificationToken) {
		if (await comparePassword(token, user.emailVerificationToken)) {
			matchedUser = user;
			break;
		}
	}
	if (!matchedUser) throw new BadRequestError("Invalid or expired verification token");
	await prisma.user.update({
		where: { id: matchedUser.id },
		data: {
			emailVerified: true,
			emailVerificationToken: null,
			emailVerificationExpires: null
		}
	});
	await createAuditLog({
		userId: matchedUser.id,
		action: "EMAIL_VERIFIED",
		entity: "User",
		entityId: matchedUser.id
	});
}
/**
* Resend verification email
*/
async function resendVerificationEmail(userId) {
	const user = await prisma.user.findUnique({
		where: { id: userId },
		select: {
			id: true,
			email: true,
			name: true,
			emailVerified: true
		}
	});
	if (!user) throw new BadRequestError("User not found");
	if (user.emailVerified) throw new BadRequestError("Email is already verified");
	const token = await generateEmailVerificationToken(user.id);
	await sendVerificationEmail(user.email, user.name, token);
	await createAuditLog({
		userId: user.id,
		action: "EMAIL_VERIFICATION_SENT",
		entity: "User",
		entityId: user.id
	});
}
/**
* Request password reset
*/
async function requestPasswordReset(email) {
	const user = await prisma.user.findUnique({
		where: { email },
		select: {
			id: true,
			email: true,
			name: true,
			password: true
		}
	});
	if (!user) return;
	if (!user.password) return;
	const token = nanoid(64);
	const expires = new Date(Date.now() + env.PASSWORD_RESET_TOKEN_EXPIRES_HOURS * 60 * 60 * 1e3);
	const hashedToken = await hashPassword(token);
	await prisma.user.update({
		where: { id: user.id },
		data: {
			passwordResetToken: hashedToken,
			passwordResetExpires: expires
		}
	});
	await createAuditLog({
		userId: user.id,
		action: "PASSWORD_RESET_REQUESTED",
		entity: "User",
		entityId: user.id
	});
	await sendPasswordResetEmail(user.email, user.name, token);
}
/**
* Reset password with token
*/
async function resetPassword(token, newPassword) {
	const users = await prisma.user.findMany({
		where: {
			passwordResetToken: { not: null },
			passwordResetExpires: { gt: /* @__PURE__ */ new Date() }
		},
		select: {
			id: true,
			passwordResetToken: true
		}
	});
	let matchedUser = null;
	for (const user of users) if (user.passwordResetToken) {
		if (await comparePassword(token, user.passwordResetToken)) {
			matchedUser = user;
			break;
		}
	}
	if (!matchedUser) throw new BadRequestError("Invalid or expired reset token");
	const hashedPassword = await hashPassword(newPassword);
	await prisma.user.update({
		where: { id: matchedUser.id },
		data: {
			password: hashedPassword,
			passwordResetToken: null,
			passwordResetExpires: null,
			failedLoginAttempts: 0,
			lockedUntil: null
		}
	});
	await prisma.session.deleteMany({ where: { userId: matchedUser.id } });
	await createAuditLog({
		userId: matchedUser.id,
		action: "PASSWORD_RESET_COMPLETED",
		entity: "User",
		entityId: matchedUser.id
	});
}
/**
* Change password (for logged-in users)
*/
async function changePassword(userId, currentPassword, newPassword) {
	const user = await prisma.user.findUnique({
		where: { id: userId },
		select: { password: true }
	});
	if (!user?.password) throw new BadRequestError("Cannot change password for accounts that use only social login");
	if (!await comparePassword(currentPassword, user.password)) throw new UnauthorizedError("Current password is incorrect");
	const hashedPassword = await hashPassword(newPassword);
	await prisma.user.update({
		where: { id: userId },
		data: { password: hashedPassword }
	});
	await createAuditLog({
		userId,
		action: "PASSWORD_CHANGED",
		entity: "User",
		entityId: userId
	});
}

//#endregion
//#region src/middlewares/auth.middleware.ts
/**
* Helper function to extract auth from request
*/
async function extractAuth(bearerToken, headers) {
	let user;
	let apiKey;
	console.log("extractAuth called:", {
		hasBearer: !!bearerToken,
		bearerPrefix: bearerToken ? bearerToken.substring(0, 10) + "..." : null,
		hasApiKey: !!headers["x-api-key"]
	});
	if (bearerToken) {
		const authUser = await validateSession(bearerToken);
		console.log("Bearer validation result:", { hasUser: !!authUser });
		if (authUser) user = authUser;
	}
	const apiKeyHeader = headers["x-api-key"];
	if (apiKeyHeader && !user) {
		const key = await prisma.aPIKey.findFirst({
			where: {
				key: apiKeyHeader,
				status: "ACTIVE",
				OR: [{ expiresAt: null }, { expiresAt: { gt: /* @__PURE__ */ new Date() } }]
			},
			include: { user: true }
		});
		if (key) {
			apiKey = {
				id: key.id,
				name: key.name,
				permissions: key.permissions
			};
			await prisma.aPIKey.update({
				where: { id: key.id },
				data: { lastUsedAt: /* @__PURE__ */ new Date() }
			});
			user = {
				id: key.user.id,
				email: key.user.email,
				name: key.user.name,
				phone: key.user.phone,
				avatar: key.user.avatar,
				role: key.user.role,
				createdAt: key.user.createdAt
			};
		}
	}
	return {
		user,
		apiKey
	};
}
/**
* Auth plugin - validates bearer token or API key
* Returns user and apiKey in context
*/
const authPlugin = new Elysia({ name: "auth" }).use(bearer()).derive(async ({ bearer: bearer$1, headers }) => {
	console.log("=== authPlugin.derive START ===", { hasBearer: !!bearer$1 });
	const result = await extractAuth(bearer$1, headers);
	console.log("=== authPlugin.derive END ===", { hasUser: !!result.user });
	return result;
});
/**
* Require authentication - throws if not authenticated
*/
const requireAuth = new Elysia({ name: "requireAuth" }).use(bearer()).derive(async ({ bearer: bearerToken, headers, request }) => {
	console.log("=== requireAuth.derive START ===", {
		hasBearer: !!bearerToken,
		bearerPrefix: bearerToken ? bearerToken.substring(0, 10) + "..." : null
	});
	let token = bearerToken;
	if (!token) {
		const authHeader = request.headers.get("authorization");
		if (authHeader?.startsWith("Bearer ")) {
			token = authHeader.slice(7);
			console.log("Got token from header directly:", token.substring(0, 10) + "...");
		}
	}
	const auth = await extractAuth(token, headers);
	console.log("=== requireAuth.derive END ===", { hasUser: !!auth.user });
	if (!auth.user) throw new UnauthorizedError("Authentication required");
	return auth;
});
/**
* Require specific role(s)
*/
function requireRole(...roles) {
	return new Elysia({ name: `requireRole:${roles.join(",")}` }).use(bearer()).derive(async ({ bearer: bearer$1, headers }) => {
		const auth = await extractAuth(bearer$1, headers);
		if (!auth.user) throw new UnauthorizedError("Authentication required");
		if (!roles.includes(auth.user.role)) throw new ForbiddenError(`Required role: ${roles.join(" or ")}`);
		return auth;
	});
}
/**
* Require admin role
*/
const requireAdmin = requireRole("ADMIN");
/**
* Require vendor role
*/
const requireVendor = requireRole("VENDOR");
/**
* Require vendor or admin role
*/
const requireVendorOrAdmin = requireRole("VENDOR", "ADMIN");

//#endregion
//#region src/utils/response.ts
/**
* Create success response
*/
function success(data, message) {
	return {
		success: true,
		data,
		message
	};
}
/**
* Create paginated success response
*/
function paginated(result) {
	return {
		success: true,
		data: result.items,
		meta: result.meta
	};
}
/**
* Parse pagination params
*/
function parsePagination(params) {
	const page = Math.max(1, params.page || 1);
	const limit = Math.min(100, Math.max(1, params.limit || 20));
	return {
		page,
		limit,
		skip: (page - 1) * limit
	};
}
/**
* Create pagination meta
*/
function createPaginationMeta(page, limit, total) {
	return {
		page,
		limit,
		total,
		totalPages: Math.ceil(total / limit)
	};
}

//#endregion
//#region src/utils/validation.ts
const idSchema = z.string().min(1, "ID is required");
const paginationSchema = z.object({
	page: z.coerce.number().int().positive().optional().default(1),
	limit: z.coerce.number().int().positive().max(100).optional().default(20)
});
const emailSchema = z.string().email("Invalid email format");
const phoneSchema = z.string().regex(/^[0-9]{9,10}$/, "Phone must be 9-10 digits").optional();
const strongPasswordSchema = z.string().min(12, "Password must be at least 12 characters").regex(/[A-Z]/, "Password must contain at least one uppercase letter").regex(/[a-z]/, "Password must contain at least one lowercase letter").regex(/[0-9]/, "Password must contain at least one number").regex(/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/, "Password must contain at least one special character");
const registerSchema = z.object({
	email: emailSchema,
	name: z.string().min(2, "Name must be at least 2 characters"),
	phone: phoneSchema,
	password: strongPasswordSchema,
	role: z.enum(["CUSTOMER", "VENDOR"]).default("CUSTOMER")
});
const loginSchema = z.object({
	email: emailSchema,
	password: z.string().min(1, "Password is required")
});
const updateProfileSchema = z.object({
	name: z.string().min(2).optional(),
	phone: phoneSchema,
	avatar: z.string().url().optional()
});
const passwordResetRequestSchema = z.object({ email: emailSchema });
const passwordResetSchema = z.object({
	token: z.string().min(1, "Reset token is required"),
	password: strongPasswordSchema,
	confirmPassword: z.string()
}).refine((data) => data.password === data.confirmPassword, {
	message: "Passwords do not match",
	path: ["confirmPassword"]
});
const changePasswordSchema = z.object({
	currentPassword: z.string().min(1, "Current password is required"),
	newPassword: strongPasswordSchema,
	confirmPassword: z.string()
}).refine((data) => data.newPassword === data.confirmPassword, {
	message: "Passwords do not match",
	path: ["confirmPassword"]
});
const createVendorSchema = z.object({
	name: z.string().min(2, "Vendor name must be at least 2 characters"),
	description: z.string().optional(),
	categories: z.array(z.string()).optional().default([])
});
const updateVendorSchema = z.object({
	name: z.string().min(2).optional(),
	description: z.string().optional(),
	image: z.string().url().optional(),
	isOpen: z.boolean().optional(),
	categories: z.array(z.string()).optional()
});
const createMenuItemSchema = z.object({
	name: z.string().min(2, "Menu item name must be at least 2 characters"),
	description: z.string().optional(),
	price: z.number().positive("Price must be positive"),
	category: z.string().min(1, "Category is required"),
	preparationTime: z.number().int().positive().optional().default(10),
	isAvailable: z.boolean().optional().default(true)
});
const updateMenuItemSchema = z.object({
	name: z.string().min(2).optional(),
	description: z.string().optional(),
	price: z.number().positive().optional(),
	image: z.string().url().optional(),
	category: z.string().optional(),
	preparationTime: z.number().int().positive().optional(),
	isAvailable: z.boolean().optional()
});
const reservationItemSchema = z.object({
	menuItemId: z.string().min(1),
	quantity: z.number().int().positive()
});
const createReservationSchema = z.object({
	vendorId: z.string().min(1, "Vendor ID is required"),
	timeSlotId: z.string().min(1, "Time slot is required"),
	customerName: z.string().min(2, "Customer name is required"),
	customerContact: z.string().min(1, "Contact is required"),
	paymentMethod: z.enum(["CASH", "BANK_TRANSFER"]),
	items: z.array(reservationItemSchema).min(1, "At least one item is required"),
	notes: z.string().optional()
});
const updateReservationStatusSchema = z.object({ status: z.enum([
	"PENDING",
	"CONFIRMED",
	"PREPARING",
	"READY",
	"COMPLETED",
	"CANCELLED"
]) });
const createTimeSlotSchema = z.object({
	label: z.string().min(1),
	startTime: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, "Invalid time format (HH:mm)"),
	endTime: z.string().regex(/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/, "Invalid time format (HH:mm)"),
	period: z.enum(["MORNING", "AFTERNOON"]),
	maxOrders: z.number().int().positive().optional().default(50)
});
const createReviewSchema = z.object({
	vendorId: z.string().min(1),
	rating: z.number().int().min(1).max(5),
	comment: z.string().optional(),
	images: z.array(z.string().url()).optional().default([])
});
const createApiKeySchema = z.object({
	name: z.string().min(2, "API key name must be at least 2 characters"),
	permissions: z.array(z.string()).optional().default(["read"]),
	expiresAt: z.string().datetime().optional()
});
const updateUserRoleSchema = z.object({ role: z.enum([
	"CUSTOMER",
	"VENDOR",
	"ADMIN"
]) });
const createUserSchema = z.object({
	email: emailSchema,
	name: z.string().min(2),
	phone: phoneSchema,
	role: z.enum([
		"CUSTOMER",
		"VENDOR",
		"ADMIN"
	]).default("CUSTOMER")
});

//#endregion
//#region src/controllers/auth.controller.ts
const google = new Google(env.GOOGLE_CLIENT_ID, env.GOOGLE_CLIENT_SECRET, env.GOOGLE_CALLBACK_URL);
const oauthStore = /* @__PURE__ */ new Map();
setInterval(() => {
	const now = Date.now();
	for (const [key, value] of oauthStore.entries()) if (value.expiresAt < now) oauthStore.delete(key);
}, 6e4);
const authController = new Elysia({ prefix: "/auth" }).get("/health", () => success({ status: "ok" })).post("/register", async ({ body }) => {
	const validated = registerSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	const session = await register(validated.data);
	return success({
		user: session.user,
		token: session.token,
		expiresAt: session.expiresAt
	}, "Registration successful");
}, {
	body: t.Object({
		email: t.String(),
		name: t.String(),
		phone: t.Optional(t.String()),
		password: t.String(),
		role: t.Optional(t.Union([t.Literal("CUSTOMER"), t.Literal("VENDOR")]))
	}),
	detail: {
		tags: ["Auth"],
		summary: "Register new user",
		description: "Register a new user with email and password"
	}
}).post("/login", async ({ body }) => {
	const validated = loginSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	const session = await login(validated.data);
	return success({
		user: session.user,
		token: session.token,
		expiresAt: session.expiresAt
	}, "Login successful");
}, {
	body: t.Object({
		email: t.String(),
		password: t.String()
	}),
	detail: {
		tags: ["Auth"],
		summary: "Login",
		description: "Login with email and password"
	}
}).get("/google", async ({ redirect }) => {
	const state = crypto.randomUUID();
	const codeVerifier = crypto.randomUUID() + crypto.randomUUID();
	const url = await google.createAuthorizationURL(state, codeVerifier, { scopes: [
		"openid",
		"profile",
		"email"
	] });
	oauthStore.set(state, {
		codeVerifier,
		expiresAt: Date.now() + 600 * 1e3
	});
	url.searchParams.set("access_type", "offline");
	url.searchParams.set("prompt", "consent");
	return redirect(url.toString());
}, { detail: {
	tags: ["Auth"],
	summary: "Google OAuth",
	description: "Start Google OAuth flow"
} }).get("/google/callback", async ({ query, redirect }) => {
	const { code, state, error } = query;
	if (error || !code) return redirect(`${env.FRONTEND_URL}/login?error=oauth_failed`);
	try {
		const storedData = state ? oauthStore.get(state) : null;
		if (!storedData) {
			console.error("OAuth state not found or expired");
			return redirect(`${env.FRONTEND_URL}/login?error=oauth_expired`);
		}
		oauthStore.delete(state);
		const tokens = await google.validateAuthorizationCode(code, storedData.codeVerifier);
		const response = await fetch("https://www.googleapis.com/oauth2/v3/userinfo", { headers: { Authorization: `Bearer ${tokens.accessToken}` } });
		if (!response.ok) throw new Error("Failed to fetch user info");
		const googleUser = await response.json();
		const session = await googleAuth({
			id: googleUser.sub,
			email: googleUser.email,
			name: googleUser.name,
			picture: googleUser.picture
		}, {
			accessToken: tokens.accessToken,
			refreshToken: tokens.refreshToken ?? void 0,
			expiresAt: tokens.accessTokenExpiresAt ? Math.floor(tokens.accessTokenExpiresAt.getTime() / 1e3) : void 0
		});
		console.log("Google OAuth session created:", {
			userId: session.user.id,
			email: session.user.email,
			tokenPrefix: session.token.substring(0, 10) + "...",
			expiresAt: session.expiresAt
		});
		const redirectUrl = new URL(`${env.FRONTEND_URL}/auth/callback`);
		redirectUrl.searchParams.set("token", session.token);
		redirectUrl.searchParams.set("expires", session.expiresAt.toISOString());
		return redirect(redirectUrl.toString());
	} catch (err) {
		console.error("Google OAuth error:", err);
		return redirect(`${env.FRONTEND_URL}/login?error=oauth_failed`);
	}
}, {
	query: t.Object({
		code: t.Optional(t.String()),
		state: t.Optional(t.String()),
		error: t.Optional(t.String())
	}),
	detail: {
		tags: ["Auth"],
		summary: "Google OAuth Callback",
		description: "Handle Google OAuth callback"
	}
}).use(authPlugin).get("/me", async (ctx) => {
	let { user, bearer: bearer$1 } = ctx;
	console.log("/auth/me called:", {
		hasBearer: !!bearer$1,
		bearerPrefix: bearer$1 ? bearer$1.substring(0, 10) + "..." : null,
		hasUser: !!user,
		userId: user?.id
	});
	if (!user && bearer$1) {
		console.log("Attempting direct session validation...");
		const validatedUser = await validateSession(bearer$1);
		console.log("Direct validation result:", { hasUser: !!validatedUser });
		if (validatedUser) return success(validatedUser);
	}
	if (!user) return {
		success: true,
		data: null,
		message: "Not authenticated",
		debug: {
			hasBearer: !!bearer$1,
			bearerPrefix: bearer$1 ? bearer$1.substring(0, 10) + "..." : null
		}
	};
	return success(user);
}, { detail: {
	tags: ["Auth"],
	summary: "Get current user",
	description: "Get currently authenticated user"
} }).use(requireAuth).post("/logout", async (ctx) => {
	const { bearer: bearer$1 } = ctx;
	if (bearer$1) await logout(bearer$1);
	return success(null, "Logged out successfully");
}, { detail: {
	tags: ["Auth"],
	summary: "Logout",
	description: "Logout current session"
} }).post("/logout-all", async (ctx) => {
	const { user } = ctx;
	await logoutAll(user.id);
	return success(null, "All sessions logged out");
}, { detail: {
	tags: ["Auth"],
	summary: "Logout all",
	description: "Logout all sessions for current user"
} }).get("/sessions", async (ctx) => {
	const { user } = ctx;
	return success(await getUserSessions(user.id));
}, { detail: {
	tags: ["Auth"],
	summary: "Get sessions",
	description: "Get all active sessions for current user"
} }).delete("/sessions/:sessionId", async (ctx) => {
	const { user, params } = ctx;
	await deleteSession(user.id, params.sessionId);
	return success(null, "Session deleted");
}, {
	params: t.Object({ sessionId: t.String() }),
	detail: {
		tags: ["Auth"],
		summary: "Delete session",
		description: "Delete a specific session"
	}
}).post("/change-password", async ({ body, ...ctx }) => {
	const { user } = ctx;
	const validated = changePasswordSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	await changePassword(user.id, validated.data.currentPassword, validated.data.newPassword);
	return success(null, "Password changed successfully");
}, {
	body: t.Object({
		currentPassword: t.String(),
		newPassword: t.String(),
		confirmPassword: t.String()
	}),
	detail: {
		tags: ["Auth"],
		summary: "Change password",
		description: "Change password for authenticated user"
	}
}).post("/resend-verification", async (ctx) => {
	const { user } = ctx;
	await resendVerificationEmail(user.id);
	return success(null, "Verification email sent");
}, { detail: {
	tags: ["Auth"],
	summary: "Resend verification email",
	description: "Resend email verification link"
} });
const passwordResetController = new Elysia({ prefix: "/auth" }).post("/forgot-password", async ({ body }) => {
	const validated = passwordResetRequestSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	await requestPasswordReset(validated.data.email);
	return success(null, "If an account exists with this email, a password reset link has been sent.");
}, {
	body: t.Object({ email: t.String() }),
	detail: {
		tags: ["Auth"],
		summary: "Request password reset",
		description: "Request a password reset email"
	}
}).post("/reset-password", async ({ body }) => {
	const validated = passwordResetSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	const passwordValidation = strongPasswordSchema.safeParse(validated.data.password);
	if (!passwordValidation.success) throw new BadRequestError(passwordValidation.error.errors[0].message);
	await resetPassword(validated.data.token, validated.data.password);
	return success(null, "Password has been reset successfully. Please login with your new password.");
}, {
	body: t.Object({
		token: t.String(),
		password: t.String(),
		confirmPassword: t.String()
	}),
	detail: {
		tags: ["Auth"],
		summary: "Reset password",
		description: "Reset password using reset token"
	}
}).post("/verify-email", async ({ body }) => {
	await verifyEmail(body.token);
	return success(null, "Email verified successfully");
}, {
	body: t.Object({ token: t.String() }),
	detail: {
		tags: ["Auth"],
		summary: "Verify email",
		description: "Verify email address with token"
	}
}).post("/test-email", async ({ body }) => {
	const { sendTestEmail: sendTestEmail$1 } = await import("./email.service-8WJwX3nu.mjs");
	const result = await sendTestEmail$1(body.email);
	return result.success ? success(result, result.message) : {
		success: false,
		error: result.message
	};
}, {
	body: t.Object({ email: t.String() }),
	detail: {
		tags: ["Auth"],
		summary: "Test email",
		description: "Send a test email to verify SMTP configuration"
	}
});

//#endregion
//#region src/services/user.service.ts
/**
* Get user by ID
*/
async function getUserById(userId) {
	const user = await prisma.user.findUnique({
		where: { id: userId },
		select: {
			id: true,
			email: true,
			name: true,
			phone: true,
			avatar: true,
			role: true,
			isActive: true,
			createdAt: true,
			updatedAt: true
		}
	});
	if (!user) throw new NotFoundError("User");
	return user;
}
/**
* Update user profile
*/
async function updateProfile(userId, input) {
	if (!await prisma.user.findUnique({ where: { id: userId } })) throw new NotFoundError("User");
	return await prisma.user.update({
		where: { id: userId },
		data: {
			name: input.name,
			phone: input.phone,
			avatar: input.avatar
		},
		select: {
			id: true,
			email: true,
			name: true,
			phone: true,
			avatar: true,
			role: true,
			isActive: true,
			createdAt: true,
			updatedAt: true
		}
	});
}
/**
* Get all users (admin only)
*/
async function getAllUsers(pagination, filters) {
	const { page, limit, skip } = parsePagination(pagination);
	const where = {};
	if (filters?.role) where.role = filters.role;
	if (filters?.isActive !== void 0) where.isActive = filters.isActive;
	if (filters?.search) where.OR = [{ name: {
		contains: filters.search,
		mode: "insensitive"
	} }, { email: {
		contains: filters.search,
		mode: "insensitive"
	} }];
	const [users, total] = await Promise.all([prisma.user.findMany({
		where,
		select: {
			id: true,
			email: true,
			name: true,
			phone: true,
			avatar: true,
			role: true,
			isActive: true,
			createdAt: true,
			updatedAt: true
		},
		orderBy: { createdAt: "desc" },
		skip,
		take: limit
	}), prisma.user.count({ where })]);
	return {
		items: users,
		meta: createPaginationMeta(page, limit, total)
	};
}
/**
* Update user role (admin only)
*/
async function updateUserRole(userId, role) {
	if (!await prisma.user.findUnique({ where: { id: userId } })) throw new NotFoundError("User");
	return await prisma.user.update({
		where: { id: userId },
		data: { role },
		select: {
			id: true,
			email: true,
			name: true,
			phone: true,
			avatar: true,
			role: true,
			isActive: true,
			createdAt: true,
			updatedAt: true
		}
	});
}
/**
* Toggle user active status (admin only)
*/
async function toggleUserStatus(userId) {
	const user = await prisma.user.findUnique({ where: { id: userId } });
	if (!user) throw new NotFoundError("User");
	return await prisma.user.update({
		where: { id: userId },
		data: { isActive: !user.isActive },
		select: {
			id: true,
			email: true,
			name: true,
			phone: true,
			avatar: true,
			role: true,
			isActive: true,
			createdAt: true,
			updatedAt: true
		}
	});
}
/**
* Delete user (admin only)
*/
async function deleteUser(userId) {
	if (!await prisma.user.findUnique({ where: { id: userId } })) throw new NotFoundError("User");
	await prisma.user.delete({ where: { id: userId } });
}
/**
* Update user password (admin only)
*/
async function updateUserPassword(userId, newPassword) {
	if (!await prisma.user.findUnique({ where: { id: userId } })) throw new NotFoundError("User");
	const hashedPassword = await Bun.password.hash(newPassword, {
		algorithm: "bcrypt",
		cost: 10
	});
	return await prisma.user.update({
		where: { id: userId },
		data: { password: hashedPassword },
		select: {
			id: true,
			email: true,
			name: true,
			phone: true,
			avatar: true,
			role: true,
			isActive: true,
			createdAt: true,
			updatedAt: true
		}
	});
}
/**
* Get user statistics
*/
async function getUserStats() {
	const [total, customers, vendors, admins, active, inactive] = await Promise.all([
		prisma.user.count(),
		prisma.user.count({ where: { role: "CUSTOMER" } }),
		prisma.user.count({ where: { role: "VENDOR" } }),
		prisma.user.count({ where: { role: "ADMIN" } }),
		prisma.user.count({ where: { isActive: true } }),
		prisma.user.count({ where: { isActive: false } })
	]);
	return {
		total,
		byRole: {
			customers,
			vendors,
			admins
		},
		byStatus: {
			active,
			inactive
		}
	};
}

//#endregion
//#region src/controllers/user.controller.ts
async function getAuthUser$5(request) {
	const authHeader = request.headers.get("authorization");
	if (!authHeader?.startsWith("Bearer ")) throw new UnauthorizedError("Authentication required");
	const user = await validateSession(authHeader.slice(7));
	if (!user) throw new UnauthorizedError("Invalid or expired session");
	return user;
}
async function getAdminUser(request) {
	const user = await getAuthUser$5(request);
	if (user.role !== "ADMIN") throw new ForbiddenError("Admin access required");
	return user;
}
const userController = new Elysia({ prefix: "/users" }).use(bearer()).get("/me", async ({ request }) => {
	const user = await getAuthUser$5(request);
	return success(await getUserById(user.id));
}, { detail: {
	tags: ["Users"],
	summary: "Get my profile",
	description: "Get current user profile"
} }).patch("/me", async ({ request, body }) => {
	const user = await getAuthUser$5(request);
	const validated = updateProfileSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	return success(await updateProfile(user.id, validated.data), "Profile updated");
}, {
	body: t.Object({
		name: t.Optional(t.String()),
		phone: t.Optional(t.String()),
		avatar: t.Optional(t.String())
	}),
	detail: {
		tags: ["Users"],
		summary: "Update my profile",
		description: "Update current user profile"
	}
}).get("/stats/overview", async ({ request }) => {
	await getAdminUser(request);
	return success(await getUserStats());
}, { detail: {
	tags: ["Users"],
	summary: "Get user statistics",
	description: "Get user statistics (admin only)"
} }).get("/", async ({ request, query }) => {
	await getAdminUser(request);
	const pagination = paginationSchema.safeParse(query);
	const paginationData = pagination.success ? pagination.data : {
		page: 1,
		limit: 20
	};
	return paginated(await getAllUsers(paginationData, {
		role: query.role,
		search: query.search,
		isActive: query.isActive === "true" ? true : query.isActive === "false" ? false : void 0
	}));
}, {
	query: t.Object({
		page: t.Optional(t.String()),
		limit: t.Optional(t.String()),
		role: t.Optional(t.String()),
		search: t.Optional(t.String()),
		isActive: t.Optional(t.String())
	}),
	detail: {
		tags: ["Users"],
		summary: "List all users",
		description: "Get all users (admin only)"
	}
}).get("/:userId", async ({ request, params }) => {
	await getAdminUser(request);
	return success(await getUserById(params.userId));
}, {
	params: t.Object({ userId: t.String() }),
	detail: {
		tags: ["Users"],
		summary: "Get user by ID",
		description: "Get user details by ID (admin only)"
	}
}).patch("/:userId/role", async ({ request, params, body }) => {
	await getAdminUser(request);
	return success(await updateUserRole(params.userId, body.role), "Role updated");
}, {
	params: t.Object({ userId: t.String() }),
	body: t.Object({ role: t.Union([
		t.Literal("CUSTOMER"),
		t.Literal("VENDOR"),
		t.Literal("ADMIN")
	]) }),
	detail: {
		tags: ["Users"],
		summary: "Update user role",
		description: "Update user role (admin only)"
	}
}).patch("/:userId/toggle-status", async ({ request, params }) => {
	await getAdminUser(request);
	const user = await toggleUserStatus(params.userId);
	return success(user, `User ${user.isActive ? "activated" : "deactivated"}`);
}, {
	params: t.Object({ userId: t.String() }),
	detail: {
		tags: ["Users"],
		summary: "Toggle user status",
		description: "Activate/deactivate user (admin only)"
	}
}).patch("/:userId/password", async ({ request, params, body }) => {
	await getAdminUser(request);
	if (!body.password || body.password.length < 6) throw new BadRequestError("Password must be at least 6 characters");
	return success(await updateUserPassword(params.userId, body.password), "Password updated");
}, {
	params: t.Object({ userId: t.String() }),
	body: t.Object({ password: t.String() }),
	detail: {
		tags: ["Users"],
		summary: "Update user password",
		description: "Update user password (admin only)"
	}
}).delete("/:userId", async ({ request, params }) => {
	await getAdminUser(request);
	await deleteUser(params.userId);
	return success(null, "User deleted");
}, {
	params: t.Object({ userId: t.String() }),
	detail: {
		tags: ["Users"],
		summary: "Delete user",
		description: "Delete user (admin only)"
	}
});

//#endregion
//#region src/services/apikey.service.ts
/**
* Create a new API key for a user
*/
async function createApiKey(userId, input) {
	const { key, prefix } = generateApiKey();
	const apiKey = await prisma.aPIKey.create({ data: {
		userId,
		name: input.name,
		key,
		keyPrefix: prefix,
		permissions: input.permissions,
		expiresAt: input.expiresAt ? new Date(input.expiresAt) : null
	} });
	return {
		apiKey: {
			id: apiKey.id,
			name: apiKey.name,
			keyPrefix: apiKey.keyPrefix,
			permissions: apiKey.permissions,
			status: apiKey.status,
			lastUsedAt: apiKey.lastUsedAt,
			expiresAt: apiKey.expiresAt,
			createdAt: apiKey.createdAt
		},
		key
	};
}
/**
* Get all API keys for a user
*/
async function getUserApiKeys(userId) {
	return await prisma.aPIKey.findMany({
		where: { userId },
		select: {
			id: true,
			name: true,
			keyPrefix: true,
			permissions: true,
			status: true,
			lastUsedAt: true,
			expiresAt: true,
			createdAt: true
		},
		orderBy: { createdAt: "desc" }
	});
}
/**
* Get single API key
*/
async function getApiKey(userId, keyId) {
	const apiKey = await prisma.aPIKey.findFirst({
		where: {
			id: keyId,
			userId
		},
		select: {
			id: true,
			name: true,
			keyPrefix: true,
			permissions: true,
			status: true,
			lastUsedAt: true,
			expiresAt: true,
			createdAt: true
		}
	});
	if (!apiKey) throw new NotFoundError("API Key");
	return apiKey;
}
/**
* Update API key permissions
*/
async function updateApiKeyPermissions(userId, keyId, permissions) {
	if (!await prisma.aPIKey.findFirst({ where: {
		id: keyId,
		userId
	} })) throw new NotFoundError("API Key");
	return await prisma.aPIKey.update({
		where: { id: keyId },
		data: { permissions },
		select: {
			id: true,
			name: true,
			keyPrefix: true,
			permissions: true,
			status: true,
			lastUsedAt: true,
			expiresAt: true,
			createdAt: true
		}
	});
}
/**
* Revoke an API key
*/
async function revokeApiKey(userId, keyId) {
	const apiKey = await prisma.aPIKey.findFirst({ where: {
		id: keyId,
		userId
	} });
	if (!apiKey) throw new NotFoundError("API Key");
	if (apiKey.status === "REVOKED") throw new BadRequestError("API Key is already revoked");
	return await prisma.aPIKey.update({
		where: { id: keyId },
		data: { status: "REVOKED" },
		select: {
			id: true,
			name: true,
			keyPrefix: true,
			permissions: true,
			status: true,
			lastUsedAt: true,
			expiresAt: true,
			createdAt: true
		}
	});
}
/**
* Rotate an API key (revoke old and create new)
*/
async function rotateApiKey(userId, keyId) {
	const oldKey = await prisma.aPIKey.findFirst({ where: {
		id: keyId,
		userId
	} });
	if (!oldKey) throw new NotFoundError("API Key");
	const { key, prefix } = generateApiKey();
	const [_, newApiKey] = await prisma.$transaction([prisma.aPIKey.update({
		where: { id: keyId },
		data: { status: "REVOKED" }
	}), prisma.aPIKey.create({ data: {
		userId,
		name: oldKey.name,
		key,
		keyPrefix: prefix,
		permissions: oldKey.permissions,
		expiresAt: oldKey.expiresAt
	} })]);
	return {
		apiKey: {
			id: newApiKey.id,
			name: newApiKey.name,
			keyPrefix: newApiKey.keyPrefix,
			permissions: newApiKey.permissions,
			status: newApiKey.status,
			lastUsedAt: newApiKey.lastUsedAt,
			expiresAt: newApiKey.expiresAt,
			createdAt: newApiKey.createdAt
		},
		key
	};
}
/**
* Delete an API key permanently
*/
async function deleteApiKey(userId, keyId) {
	if (!await prisma.aPIKey.findFirst({ where: {
		id: keyId,
		userId
	} })) throw new NotFoundError("API Key");
	await prisma.aPIKey.delete({ where: { id: keyId } });
}

//#endregion
//#region src/controllers/apikey.controller.ts
const apiKeyController = new Elysia({ prefix: "/api-keys" }).use(requireAuth).get("/", async (ctx) => {
	const { user } = ctx;
	return success(await getUserApiKeys(user.id));
}, { detail: {
	tags: ["API Keys"],
	summary: "List API keys",
	description: "Get all API keys for current user"
} }).post("/", async (ctx) => {
	const { user, body } = ctx;
	const validated = createApiKeySchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	return success(await createApiKey(user.id, validated.data), "API key created. Save the key now - it will not be shown again.");
}, {
	body: t.Object({
		name: t.String(),
		permissions: t.Optional(t.Array(t.String())),
		expiresAt: t.Optional(t.String())
	}),
	detail: {
		tags: ["API Keys"],
		summary: "Create API key",
		description: "Create a new API key"
	}
}).get("/:keyId", async (ctx) => {
	const { user, params } = ctx;
	return success(await getApiKey(user.id, params.keyId));
}, {
	params: t.Object({ keyId: t.String() }),
	detail: {
		tags: ["API Keys"],
		summary: "Get API key",
		description: "Get details of a specific API key"
	}
}).patch("/:keyId/permissions", async (ctx) => {
	const { user, params, body } = ctx;
	return success(await updateApiKeyPermissions(user.id, params.keyId, body.permissions), "Permissions updated");
}, {
	params: t.Object({ keyId: t.String() }),
	body: t.Object({ permissions: t.Array(t.String()) }),
	detail: {
		tags: ["API Keys"],
		summary: "Update permissions",
		description: "Update API key permissions"
	}
}).post("/:keyId/revoke", async (ctx) => {
	const { user, params } = ctx;
	return success(await revokeApiKey(user.id, params.keyId), "API key revoked");
}, {
	params: t.Object({ keyId: t.String() }),
	detail: {
		tags: ["API Keys"],
		summary: "Revoke API key",
		description: "Revoke an API key (cannot be undone)"
	}
}).post("/:keyId/rotate", async (ctx) => {
	const { user, params } = ctx;
	return success(await rotateApiKey(user.id, params.keyId), "API key rotated. Save the new key now - it will not be shown again.");
}, {
	params: t.Object({ keyId: t.String() }),
	detail: {
		tags: ["API Keys"],
		summary: "Rotate API key",
		description: "Revoke old key and generate a new one with same permissions"
	}
}).delete("/:keyId", async (ctx) => {
	const { user, params } = ctx;
	await deleteApiKey(user.id, params.keyId);
	return success(null, "API key deleted");
}, {
	params: t.Object({ keyId: t.String() }),
	detail: {
		tags: ["API Keys"],
		summary: "Delete API key",
		description: "Permanently delete an API key"
	}
});

//#endregion
//#region src/services/vendor.service.ts
/**
* Create vendor for a user
*/
async function createVendor(userId, input) {
	if (await prisma.vendor.findUnique({ where: { userId } })) throw new ConflictError("User already has a vendor profile");
	const [vendor] = await prisma.$transaction([prisma.vendor.create({
		data: {
			userId,
			name: input.name,
			description: input.description,
			categories: input.categories
		},
		include: { user: { select: {
			id: true,
			email: true,
			name: true,
			avatar: true
		} } }
	}), prisma.user.update({
		where: { id: userId },
		data: { role: "VENDOR" }
	})]);
	return vendor;
}
/**
* Get vendor by ID
*/
async function getVendorById(vendorId) {
	const vendor = await prisma.vendor.findUnique({
		where: { id: vendorId },
		include: { user: { select: {
			id: true,
			email: true,
			name: true,
			avatar: true
		} } }
	});
	if (!vendor) throw new NotFoundError("Vendor");
	return vendor;
}
/**
* Get vendor by user ID
*/
async function getVendorByUserId(userId) {
	const vendor = await prisma.vendor.findUnique({
		where: { userId },
		include: { user: { select: {
			id: true,
			email: true,
			name: true,
			avatar: true
		} } }
	});
	if (!vendor) throw new NotFoundError("Vendor");
	return vendor;
}
/**
* Update vendor
*/
async function updateVendor(vendorId, userId, userRole, input) {
	const vendor = await prisma.vendor.findUnique({ where: { id: vendorId } });
	if (!vendor) throw new NotFoundError("Vendor");
	if (vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to update this vendor");
	return await prisma.vendor.update({
		where: { id: vendorId },
		data: {
			name: input.name,
			description: input.description,
			image: input.image,
			isOpen: input.isOpen,
			categories: input.categories
		},
		include: { user: { select: {
			id: true,
			email: true,
			name: true,
			avatar: true
		} } }
	});
}
/**
* Get all vendors with pagination and filters
*/
async function getAllVendors(pagination, filters) {
	const { page, limit, skip } = parsePagination(pagination);
	const where = {};
	if (filters?.isOpen !== void 0) where.isOpen = filters.isOpen;
	if (filters?.category) where.categories = { has: filters.category };
	if (filters?.search) where.OR = [{ name: {
		contains: filters.search,
		mode: "insensitive"
	} }, { description: {
		contains: filters.search,
		mode: "insensitive"
	} }];
	const [vendors, total] = await Promise.all([prisma.vendor.findMany({
		where,
		include: { user: { select: {
			id: true,
			email: true,
			name: true,
			avatar: true
		} } },
		orderBy: [{ rating: "desc" }, { totalOrders: "desc" }],
		skip,
		take: limit
	}), prisma.vendor.count({ where })]);
	return {
		items: vendors,
		meta: createPaginationMeta(page, limit, total)
	};
}
/**
* Toggle vendor open/close status
*/
async function toggleVendorStatus(vendorId, userId, userRole) {
	const vendor = await prisma.vendor.findUnique({ where: { id: vendorId } });
	if (!vendor) throw new NotFoundError("Vendor");
	if (vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to update this vendor");
	return await prisma.vendor.update({
		where: { id: vendorId },
		data: { isOpen: !vendor.isOpen },
		include: { user: { select: {
			id: true,
			email: true,
			name: true,
			avatar: true
		} } }
	});
}
/**
* Delete vendor (admin only)
*/
async function deleteVendor(vendorId) {
	const vendor = await prisma.vendor.findUnique({ where: { id: vendorId } });
	if (!vendor) throw new NotFoundError("Vendor");
	await prisma.$transaction([prisma.vendor.delete({ where: { id: vendorId } }), prisma.user.update({
		where: { id: vendor.userId },
		data: { role: "CUSTOMER" }
	})]);
}
/**
* Get vendor statistics
*/
async function getVendorStats(vendorId) {
	const vendor = await prisma.vendor.findUnique({
		where: { id: vendorId },
		include: {
			_count: { select: {
				menuItems: true,
				reservations: true,
				reviews: true
			} },
			reservations: {
				where: { createdAt: { gte: new Date((/* @__PURE__ */ new Date()).setHours(0, 0, 0, 0)) } },
				select: {
					status: true,
					totalAmount: true
				}
			}
		}
	});
	if (!vendor) throw new NotFoundError("Vendor");
	const todayReservations = vendor.reservations;
	const todayRevenue = todayReservations.filter((r) => r.status === "COMPLETED").reduce((sum, r) => sum + r.totalAmount, 0);
	return {
		menuItemsCount: vendor._count.menuItems,
		totalReservations: vendor._count.reservations,
		reviewsCount: vendor._count.reviews,
		rating: vendor.rating,
		totalOrders: vendor.totalOrders,
		today: {
			reservations: todayReservations.length,
			revenue: todayRevenue,
			pending: todayReservations.filter((r) => r.status === "PENDING").length,
			preparing: todayReservations.filter((r) => r.status === "PREPARING").length,
			completed: todayReservations.filter((r) => r.status === "COMPLETED").length
		}
	};
}
/**
* Get all categories from all vendors
*/
async function getAllCategories() {
	const allCategories = (await prisma.vendor.findMany({ select: { categories: true } })).flatMap((v) => v.categories);
	return [...new Set(allCategories)].sort();
}

//#endregion
//#region src/controllers/vendor.controller.ts
async function getAuthUser$4(request) {
	const authHeader = request.headers.get("authorization");
	if (!authHeader?.startsWith("Bearer ")) throw new UnauthorizedError("Authentication required");
	const user = await validateSession(authHeader.slice(7));
	if (!user) throw new UnauthorizedError("Invalid or expired session");
	return user;
}
const vendorController = new Elysia({ prefix: "/vendors" }).use(authPlugin).get("/", async ({ query }) => {
	const paginationResult = paginationSchema.safeParse(query);
	const pagination = paginationResult.success ? paginationResult.data : {
		page: 1,
		limit: 10
	};
	return paginated(await getAllVendors(pagination, {
		isOpen: query.isOpen === "true" ? true : query.isOpen === "false" ? false : void 0,
		category: query.category,
		search: query.search
	}));
}, {
	query: t.Object({
		page: t.Optional(t.String()),
		limit: t.Optional(t.String()),
		isOpen: t.Optional(t.String()),
		category: t.Optional(t.String()),
		search: t.Optional(t.String())
	}),
	detail: {
		tags: ["Vendors"],
		summary: "List all vendors",
		description: "Get all vendors with optional filters"
	}
}).get("/categories", async () => {
	return success(await getAllCategories());
}, { detail: {
	tags: ["Vendors"],
	summary: "Get all categories",
	description: "Get list of all vendor categories"
} }).get("/:vendorId", async ({ params }) => {
	return success(await getVendorById(params.vendorId));
}, {
	params: t.Object({ vendorId: t.String() }),
	detail: {
		tags: ["Vendors"],
		summary: "Get vendor by ID",
		description: "Get vendor details"
	}
}).use(requireAuth).get("/me/profile", async ({ request }) => {
	const user = await getAuthUser$4(request);
	return success(await getVendorByUserId(user.id));
}, { detail: {
	tags: ["Vendors"],
	summary: "Get my vendor profile",
	description: "Get current user vendor profile"
} }).post("/", async ({ request, body }) => {
	const user = await getAuthUser$4(request);
	const validated = createVendorSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	return success(await createVendor(user.id, validated.data), "Vendor profile created");
}, {
	body: t.Object({
		name: t.String(),
		description: t.Optional(t.String()),
		categories: t.Optional(t.Array(t.String()))
	}),
	detail: {
		tags: ["Vendors"],
		summary: "Create vendor",
		description: "Create a vendor profile (become a vendor)"
	}
}).use(requireVendorOrAdmin).patch("/:vendorId", async ({ request, params, body }) => {
	const user = await getAuthUser$4(request);
	const validated = updateVendorSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	return success(await updateVendor(params.vendorId, user.id, user.role, validated.data), "Vendor updated");
}, {
	params: t.Object({ vendorId: t.String() }),
	body: t.Object({
		name: t.Optional(t.String()),
		description: t.Optional(t.String()),
		image: t.Optional(t.String()),
		isOpen: t.Optional(t.Boolean()),
		categories: t.Optional(t.Array(t.String()))
	}),
	detail: {
		tags: ["Vendors"],
		summary: "Update vendor",
		description: "Update vendor details"
	}
}).post("/:vendorId/toggle-status", async ({ request, params }) => {
	const user = await getAuthUser$4(request);
	const vendor = await toggleVendorStatus(params.vendorId, user.id, user.role);
	return success(vendor, `Shop is now ${vendor.isOpen ? "open" : "closed"}`);
}, {
	params: t.Object({ vendorId: t.String() }),
	detail: {
		tags: ["Vendors"],
		summary: "Toggle vendor status",
		description: "Open/close vendor shop"
	}
}).get("/:vendorId/stats", async ({ params }) => {
	return success(await getVendorStats(params.vendorId));
}, {
	params: t.Object({ vendorId: t.String() }),
	detail: {
		tags: ["Vendors"],
		summary: "Get vendor stats",
		description: "Get vendor statistics"
	}
}).use(requireAdmin).delete("/:vendorId", async ({ params }) => {
	await deleteVendor(params.vendorId);
	return success(null, "Vendor deleted");
}, {
	params: t.Object({ vendorId: t.String() }),
	detail: {
		tags: ["Vendors"],
		summary: "Delete vendor",
		description: "Delete vendor (admin only)"
	}
});

//#endregion
//#region src/services/menu.service.ts
/**
* Create menu item for a vendor
*/
async function createMenuItem(vendorId, userId, userRole, input) {
	const vendor = await prisma.vendor.findUnique({ where: { id: vendorId } });
	if (!vendor) throw new NotFoundError("Vendor");
	if (vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to add menu items to this vendor");
	return await prisma.menuItem.create({
		data: {
			vendorId,
			name: input.name,
			description: input.description,
			price: input.price,
			category: input.category,
			preparationTime: input.preparationTime,
			isAvailable: input.isAvailable
		},
		include: { vendor: { select: {
			id: true,
			name: true,
			isOpen: true
		} } }
	});
}
/**
* Get menu item by ID
*/
async function getMenuItemById(menuItemId) {
	const menuItem = await prisma.menuItem.findUnique({
		where: { id: menuItemId },
		include: { vendor: { select: {
			id: true,
			name: true,
			isOpen: true
		} } }
	});
	if (!menuItem) throw new NotFoundError("Menu item");
	return menuItem;
}
/**
* Update menu item
*/
async function updateMenuItem(menuItemId, userId, userRole, input) {
	const menuItem = await prisma.menuItem.findUnique({
		where: { id: menuItemId },
		include: { vendor: true }
	});
	if (!menuItem) throw new NotFoundError("Menu item");
	if (menuItem.vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to update this menu item");
	return await prisma.menuItem.update({
		where: { id: menuItemId },
		data: {
			name: input.name,
			description: input.description,
			price: input.price,
			image: input.image,
			category: input.category,
			preparationTime: input.preparationTime,
			isAvailable: input.isAvailable
		},
		include: { vendor: { select: {
			id: true,
			name: true,
			isOpen: true
		} } }
	});
}
/**
* Delete menu item
*/
async function deleteMenuItem(menuItemId, userId, userRole) {
	const menuItem = await prisma.menuItem.findUnique({
		where: { id: menuItemId },
		include: { vendor: true }
	});
	if (!menuItem) throw new NotFoundError("Menu item");
	if (menuItem.vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to delete this menu item");
	await prisma.menuItem.delete({ where: { id: menuItemId } });
}
/**
* Get menu items for a vendor
*/
async function getVendorMenuItems(vendorId, pagination, filters) {
	const { page, limit, skip } = parsePagination(pagination);
	const where = { vendorId };
	if (filters?.category) where.category = filters.category;
	if (filters?.isAvailable !== void 0) where.isAvailable = filters.isAvailable;
	if (filters?.search) where.OR = [{ name: {
		contains: filters.search,
		mode: "insensitive"
	} }, { description: {
		contains: filters.search,
		mode: "insensitive"
	} }];
	const [menuItems, total] = await Promise.all([prisma.menuItem.findMany({
		where,
		include: { vendor: { select: {
			id: true,
			name: true,
			isOpen: true
		} } },
		orderBy: [{ category: "asc" }, { name: "asc" }],
		skip,
		take: limit
	}), prisma.menuItem.count({ where })]);
	return {
		items: menuItems,
		meta: createPaginationMeta(page, limit, total)
	};
}
/**
* Toggle menu item availability
*/
async function toggleMenuItemAvailability(menuItemId, userId, userRole) {
	const menuItem = await prisma.menuItem.findUnique({
		where: { id: menuItemId },
		include: { vendor: true }
	});
	if (!menuItem) throw new NotFoundError("Menu item");
	if (menuItem.vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to update this menu item");
	return await prisma.menuItem.update({
		where: { id: menuItemId },
		data: { isAvailable: !menuItem.isAvailable },
		include: { vendor: { select: {
			id: true,
			name: true,
			isOpen: true
		} } }
	});
}
/**
* Get all menu categories for a vendor
*/
async function getVendorCategories(vendorId) {
	return (await prisma.menuItem.findMany({
		where: { vendorId },
		select: { category: true },
		distinct: ["category"]
	})).map((item) => item.category).sort();
}
/**
* Bulk update menu item availability
*/
async function bulkUpdateAvailability(vendorId, userId, userRole, menuItemIds, isAvailable) {
	const vendor = await prisma.vendor.findUnique({ where: { id: vendorId } });
	if (!vendor) throw new NotFoundError("Vendor");
	if (vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to update menu items");
	return (await prisma.menuItem.updateMany({
		where: {
			id: { in: menuItemIds },
			vendorId
		},
		data: { isAvailable }
	})).count;
}

//#endregion
//#region src/controllers/menu.controller.ts
async function getAuthUser$3(request) {
	const authHeader = request.headers.get("authorization");
	if (!authHeader?.startsWith("Bearer ")) throw new UnauthorizedError("Authentication required");
	const user = await validateSession(authHeader.slice(7));
	if (!user) throw new UnauthorizedError("Invalid or expired session");
	return user;
}
const menuController = new Elysia({ prefix: "/menu" }).use(authPlugin).get("/:menuItemId", async ({ params }) => {
	return success(await getMenuItemById(params.menuItemId));
}, {
	params: t.Object({ menuItemId: t.String() }),
	detail: {
		tags: ["Menu"],
		summary: "Get menu item",
		description: "Get menu item details"
	}
}).use(requireAuth).use(requireVendorOrAdmin).patch("/:menuItemId", async ({ request, params, body }) => {
	const user = await getAuthUser$3(request);
	const validated = updateMenuItemSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	return success(await updateMenuItem(params.menuItemId, user.id, user.role, validated.data), "Menu item updated");
}, {
	params: t.Object({ menuItemId: t.String() }),
	body: t.Object({
		name: t.Optional(t.String()),
		description: t.Optional(t.String()),
		price: t.Optional(t.Number()),
		image: t.Optional(t.String()),
		category: t.Optional(t.String()),
		preparationTime: t.Optional(t.Number()),
		isAvailable: t.Optional(t.Boolean())
	}),
	detail: {
		tags: ["Menu"],
		summary: "Update menu item",
		description: "Update menu item details"
	}
}).post("/:menuItemId/toggle-availability", async ({ request, params }) => {
	const user = await getAuthUser$3(request);
	const menuItem = await toggleMenuItemAvailability(params.menuItemId, user.id, user.role);
	return success(menuItem, `Menu item is now ${menuItem.isAvailable ? "available" : "unavailable"}`);
}, {
	params: t.Object({ menuItemId: t.String() }),
	detail: {
		tags: ["Menu"],
		summary: "Toggle availability",
		description: "Toggle menu item availability"
	}
}).delete("/:menuItemId", async ({ request, params }) => {
	const user = await getAuthUser$3(request);
	await deleteMenuItem(params.menuItemId, user.id, user.role);
	return success(null, "Menu item deleted");
}, {
	params: t.Object({ menuItemId: t.String() }),
	detail: {
		tags: ["Menu"],
		summary: "Delete menu item",
		description: "Delete menu item"
	}
});
const vendorMenuController = new Elysia({ prefix: "/vendors/:vendorId/menu" }).use(authPlugin).get("/", async ({ params, query }) => {
	const pagination = paginationSchema.safeParse(query);
	const paginationData = pagination.success ? pagination.data : {
		page: 1,
		limit: 20
	};
	return paginated(await getVendorMenuItems(params.vendorId, paginationData, {
		category: query.category,
		isAvailable: query.isAvailable === "true" ? true : query.isAvailable === "false" ? false : void 0,
		search: query.search
	}));
}, {
	params: t.Object({ vendorId: t.String() }),
	query: t.Object({
		page: t.Optional(t.String()),
		limit: t.Optional(t.String()),
		category: t.Optional(t.String()),
		isAvailable: t.Optional(t.String()),
		search: t.Optional(t.String())
	}),
	detail: {
		tags: ["Menu"],
		summary: "Get vendor menu",
		description: "Get all menu items for a vendor"
	}
}).get("/categories", async ({ params }) => {
	return success(await getVendorCategories(params.vendorId));
}, {
	params: t.Object({ vendorId: t.String() }),
	detail: {
		tags: ["Menu"],
		summary: "Get vendor categories",
		description: "Get all menu categories for a vendor"
	}
}).use(requireAuth).use(requireVendorOrAdmin).post("/", async ({ request, params, body }) => {
	const user = await getAuthUser$3(request);
	const validated = createMenuItemSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	return success(await createMenuItem(params.vendorId, user.id, user.role, validated.data), "Menu item created");
}, {
	params: t.Object({ vendorId: t.String() }),
	body: t.Object({
		name: t.String(),
		description: t.Optional(t.String()),
		price: t.Number(),
		category: t.String(),
		preparationTime: t.Optional(t.Number()),
		isAvailable: t.Optional(t.Boolean())
	}),
	detail: {
		tags: ["Menu"],
		summary: "Create menu item",
		description: "Create a new menu item for vendor"
	}
}).post("/bulk-availability", async ({ request, params, body }) => {
	const user = await getAuthUser$3(request);
	const count = await bulkUpdateAvailability(params.vendorId, user.id, user.role, body.menuItemIds, body.isAvailable);
	return success({ updatedCount: count }, `${count} menu items updated`);
}, {
	params: t.Object({ vendorId: t.String() }),
	body: t.Object({
		menuItemIds: t.Array(t.String()),
		isAvailable: t.Boolean()
	}),
	detail: {
		tags: ["Menu"],
		summary: "Bulk update availability",
		description: "Update availability for multiple menu items"
	}
});

//#endregion
//#region src/services/reservation.service.ts
/**
* Generate queue number for today
*/
async function generateQueueNumber(vendorId) {
	const today = /* @__PURE__ */ new Date();
	today.setHours(0, 0, 0, 0);
	return ((await prisma.reservation.findFirst({
		where: {
			vendorId,
			createdAt: { gte: today }
		},
		orderBy: { queueNumber: "desc" }
	}))?.queueNumber || 0) + 1;
}
/**
* Create reservation
*/
async function createReservation(customerId, input) {
	const vendor = await prisma.vendor.findUnique({ where: { id: input.vendorId } });
	if (!vendor) throw new NotFoundError("Vendor");
	if (!vendor.isOpen) throw new BadRequestError("This vendor is currently closed");
	if (!await prisma.timeSlot.findUnique({ where: { id: input.timeSlotId } })) throw new NotFoundError("Time slot");
	const menuItemIds = input.items.map((item) => item.menuItemId);
	const menuItems = await prisma.menuItem.findMany({ where: {
		id: { in: menuItemIds },
		vendorId: input.vendorId
	} });
	if (menuItems.length !== menuItemIds.length) throw new BadRequestError("Some menu items are not found or not available");
	const unavailableItems = menuItems.filter((item) => !item.isAvailable);
	if (unavailableItems.length > 0) throw new BadRequestError(`Some items are not available: ${unavailableItems.map((i) => i.name).join(", ")}`);
	let totalAmount = 0;
	const reservationItems = input.items.map((inputItem) => {
		const menuItem = menuItems.find((m) => m.id === inputItem.menuItemId);
		const itemTotal = menuItem.price * inputItem.quantity;
		totalAmount += itemTotal;
		return {
			menuItemId: menuItem.id,
			name: menuItem.name,
			price: menuItem.price,
			quantity: inputItem.quantity
		};
	});
	const queueNumber = await generateQueueNumber(input.vendorId);
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
			items: { create: reservationItems }
		},
		include: {
			items: true,
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} },
			customer: { select: {
				id: true,
				name: true,
				email: true
			} },
			timeSlot: { select: {
				id: true,
				label: true,
				startTime: true,
				endTime: true,
				period: true
			} }
		}
	});
	await prisma.vendor.update({
		where: { id: input.vendorId },
		data: { totalOrders: { increment: 1 } }
	});
	return reservation;
}
/**
* Get reservation by ID
*/
async function getReservationById(reservationId, userId, userRole) {
	const reservation = await prisma.reservation.findUnique({
		where: { id: reservationId },
		include: {
			items: true,
			vendor: { select: {
				id: true,
				name: true,
				image: true,
				userId: true
			} },
			customer: { select: {
				id: true,
				name: true,
				email: true
			} },
			timeSlot: { select: {
				id: true,
				label: true,
				startTime: true,
				endTime: true,
				period: true
			} }
		}
	});
	if (!reservation) throw new NotFoundError("Reservation");
	const isOwner = reservation.customerId === userId;
	const isVendorOwner = reservation.vendor?.userId === userId;
	if (!isOwner && !isVendorOwner && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to view this reservation");
	return reservation;
}
/**
* Update reservation status
*/
async function updateReservationStatus(reservationId, userId, userRole, status) {
	const reservation = await prisma.reservation.findUnique({
		where: { id: reservationId },
		include: { vendor: true }
	});
	if (!reservation) throw new NotFoundError("Reservation");
	if (!(reservation.vendor.userId === userId) && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to update this reservation");
	if (userRole !== "ADMIN") {
		if (!{
			PENDING: ["CONFIRMED", "CANCELLED"],
			CONFIRMED: ["PREPARING", "CANCELLED"],
			PREPARING: ["READY", "CANCELLED"],
			READY: ["COMPLETED", "CANCELLED"],
			COMPLETED: [],
			CANCELLED: []
		}[reservation.status].includes(status)) throw new BadRequestError(`Cannot change status from ${reservation.status} to ${status}`);
	}
	const updateData = { status };
	if (status === "CONFIRMED") updateData.confirmedAt = /* @__PURE__ */ new Date();
	else if (status === "COMPLETED") updateData.completedAt = /* @__PURE__ */ new Date();
	const updated = await prisma.reservation.update({
		where: { id: reservationId },
		data: updateData,
		include: {
			items: true,
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} },
			customer: { select: {
				id: true,
				name: true,
				email: true
			} },
			timeSlot: { select: {
				id: true,
				label: true,
				startTime: true,
				endTime: true,
				period: true
			} }
		}
	});
	if (updated.customer?.email) {
		const orderDetails = {
			queueNumber: updated.queueNumber,
			vendorName: updated.vendor?.name || "ร้านค้า",
			customerName: updated.customer.name,
			items: updated.items.map((item) => ({
				name: item.name,
				quantity: item.quantity,
				price: item.price
			})),
			totalAmount: updated.totalAmount,
			timeSlot: updated.timeSlot ? `${updated.timeSlot.startTime} - ${updated.timeSlot.endTime}` : void 0
		};
		(async () => {
			try {
				switch (status) {
					case "CONFIRMED":
						await sendOrderConfirmedEmail(updated.customer.email, orderDetails);
						break;
					case "PREPARING":
						await sendOrderPreparingEmail(updated.customer.email, orderDetails);
						break;
					case "READY":
						await sendOrderReadyEmail(updated.customer.email, orderDetails);
						break;
					case "COMPLETED":
						await sendOrderCompletedEmail(updated.customer.email, orderDetails);
						break;
					case "CANCELLED":
						await sendOrderCancelledEmail(updated.customer.email, orderDetails);
						break;
				}
				console.log(`[Reservation] Status notification sent for order #${updated.queueNumber} (${status})`);
			} catch (error) {
				console.error(`[Reservation] Failed to send status notification:`, error);
			}
		})();
	}
	return updated;
}
/**
* Cancel reservation (by customer)
*/
async function cancelReservation(reservationId, userId, userRole) {
	const reservation = await prisma.reservation.findUnique({
		where: { id: reservationId },
		include: { vendor: true }
	});
	if (!reservation) throw new NotFoundError("Reservation");
	const isOwner = reservation.customerId === userId;
	const isVendorOwner = reservation.vendor.userId === userId;
	if (!isOwner && !isVendorOwner && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to cancel this reservation");
	if (!["PENDING", "CONFIRMED"].includes(reservation.status)) throw new BadRequestError("Can only cancel pending or confirmed reservations");
	const updated = await prisma.reservation.update({
		where: { id: reservationId },
		data: { status: "CANCELLED" },
		include: {
			items: true,
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} },
			customer: { select: {
				id: true,
				name: true,
				email: true
			} },
			timeSlot: { select: {
				id: true,
				label: true,
				startTime: true,
				endTime: true,
				period: true
			} }
		}
	});
	if (updated.customer?.email) {
		const orderDetails = {
			queueNumber: updated.queueNumber,
			vendorName: updated.vendor?.name || "ร้านค้า",
			customerName: updated.customer.name,
			items: updated.items.map((item) => ({
				name: item.name,
				quantity: item.quantity,
				price: item.price
			})),
			totalAmount: updated.totalAmount
		};
		sendOrderCancelledEmail(updated.customer.email, orderDetails).catch((error) => {
			console.error(`[Reservation] Failed to send cancellation email:`, error);
		});
	}
	return updated;
}
/**
* Get customer's reservations
*/
async function getCustomerReservations(customerId, pagination, filters) {
	const { page, limit, skip } = parsePagination(pagination);
	const where = { customerId };
	if (filters?.status) where.status = filters.status;
	const [reservations, total] = await Promise.all([prisma.reservation.findMany({
		where,
		include: {
			items: true,
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} },
			timeSlot: { select: {
				id: true,
				label: true,
				startTime: true,
				endTime: true,
				period: true
			} }
		},
		orderBy: { createdAt: "desc" },
		skip,
		take: limit
	}), prisma.reservation.count({ where })]);
	return {
		items: reservations,
		meta: createPaginationMeta(page, limit, total)
	};
}
/**
* Get vendor's reservations
*/
async function getVendorReservations(vendorId, userId, userRole, pagination, filters) {
	const vendor = await prisma.vendor.findUnique({ where: { id: vendorId } });
	if (!vendor) throw new NotFoundError("Vendor");
	if (vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to view these reservations");
	const { page, limit, skip } = parsePagination(pagination);
	const where = { vendorId };
	if (filters?.status) where.status = filters.status;
	if (filters?.date) {
		const startDate = new Date(filters.date);
		startDate.setHours(0, 0, 0, 0);
		const endDate = new Date(filters.date);
		endDate.setHours(23, 59, 59, 999);
		where.createdAt = {
			gte: startDate,
			lte: endDate
		};
	}
	const [reservations, total] = await Promise.all([prisma.reservation.findMany({
		where,
		include: {
			items: true,
			customer: { select: {
				id: true,
				name: true,
				email: true
			} },
			timeSlot: { select: {
				id: true,
				label: true,
				startTime: true,
				endTime: true,
				period: true
			} }
		},
		orderBy: [{ status: "asc" }, { queueNumber: "asc" }],
		skip,
		take: limit
	}), prisma.reservation.count({ where })]);
	return {
		items: reservations,
		meta: createPaginationMeta(page, limit, total)
	};
}
/**
* Get all reservations (admin)
*/
async function getAllReservations(pagination, filters) {
	const { page, limit, skip } = parsePagination(pagination);
	const where = {};
	if (filters?.status) where.status = filters.status;
	if (filters?.vendorId) where.vendorId = filters.vendorId;
	if (filters?.date) {
		const startDate = new Date(filters.date);
		startDate.setHours(0, 0, 0, 0);
		const endDate = new Date(filters.date);
		endDate.setHours(23, 59, 59, 999);
		where.createdAt = {
			gte: startDate,
			lte: endDate
		};
	}
	const [reservations, total] = await Promise.all([prisma.reservation.findMany({
		where,
		include: {
			items: true,
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} },
			customer: { select: {
				id: true,
				name: true,
				email: true
			} },
			timeSlot: { select: {
				id: true,
				label: true,
				startTime: true,
				endTime: true,
				period: true
			} }
		},
		orderBy: { createdAt: "desc" },
		skip,
		take: limit
	}), prisma.reservation.count({ where })]);
	return {
		items: reservations,
		meta: createPaginationMeta(page, limit, total)
	};
}
/**
* Get reservation statistics
*/
async function getReservationStats(vendorId) {
	const today = /* @__PURE__ */ new Date();
	today.setHours(0, 0, 0, 0);
	const where = vendorId ? { vendorId } : {};
	const [total, pending, confirmed, preparing, ready, completed, cancelled, todayCount, todayRevenue] = await Promise.all([
		prisma.reservation.count({ where }),
		prisma.reservation.count({ where: {
			...where,
			status: "PENDING"
		} }),
		prisma.reservation.count({ where: {
			...where,
			status: "CONFIRMED"
		} }),
		prisma.reservation.count({ where: {
			...where,
			status: "PREPARING"
		} }),
		prisma.reservation.count({ where: {
			...where,
			status: "READY"
		} }),
		prisma.reservation.count({ where: {
			...where,
			status: "COMPLETED"
		} }),
		prisma.reservation.count({ where: {
			...where,
			status: "CANCELLED"
		} }),
		prisma.reservation.count({ where: {
			...where,
			createdAt: { gte: today }
		} }),
		prisma.reservation.aggregate({
			where: {
				...where,
				status: "COMPLETED",
				createdAt: { gte: today }
			},
			_sum: { totalAmount: true }
		})
	]);
	return {
		total,
		byStatus: {
			pending,
			confirmed,
			preparing,
			ready,
			completed,
			cancelled
		},
		today: {
			count: todayCount,
			revenue: todayRevenue._sum.totalAmount || 0
		}
	};
}

//#endregion
//#region src/controllers/reservation.controller.ts
async function getAuthUser$2(request) {
	const authHeader = request.headers.get("authorization");
	if (!authHeader?.startsWith("Bearer ")) throw new UnauthorizedError("Authentication required");
	const user = await validateSession(authHeader.slice(7));
	if (!user) throw new UnauthorizedError("Invalid or expired session");
	return user;
}
const reservationController = new Elysia({ prefix: "/reservations" }).use(bearer()).post("/", async ({ request, body }) => {
	const user = await getAuthUser$2(request);
	const validated = createReservationSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	return success(await createReservation(user.id, validated.data), "Reservation created successfully");
}, {
	body: t.Object({
		vendorId: t.String(),
		timeSlotId: t.String(),
		customerName: t.String(),
		customerContact: t.String(),
		paymentMethod: t.Union([t.Literal("CASH"), t.Literal("BANK_TRANSFER")]),
		items: t.Array(t.Object({
			menuItemId: t.String(),
			quantity: t.Number()
		})),
		notes: t.Optional(t.String())
	}),
	detail: {
		tags: ["Reservations"],
		summary: "Create reservation",
		description: "Create a new food reservation"
	}
}).get("/me", async ({ request, query }) => {
	const user = await getAuthUser$2(request);
	const pagination = paginationSchema.safeParse(query);
	const paginationData = pagination.success ? pagination.data : {
		page: 1,
		limit: 20
	};
	return paginated(await getCustomerReservations(user.id, paginationData, { status: query.status }));
}, {
	query: t.Object({
		page: t.Optional(t.String()),
		limit: t.Optional(t.String()),
		status: t.Optional(t.String())
	}),
	detail: {
		tags: ["Reservations"],
		summary: "Get my reservations",
		description: "Get current user reservations"
	}
}).get("/:reservationId", async ({ request, params }) => {
	const user = await getAuthUser$2(request);
	return success(await getReservationById(params.reservationId, user.id, user.role));
}, {
	params: t.Object({ reservationId: t.String() }),
	detail: {
		tags: ["Reservations"],
		summary: "Get reservation",
		description: "Get reservation details"
	}
}).post("/:reservationId/cancel", async ({ request, params }) => {
	const user = await getAuthUser$2(request);
	return success(await cancelReservation(params.reservationId, user.id, user.role), "Reservation cancelled");
}, {
	params: t.Object({ reservationId: t.String() }),
	detail: {
		tags: ["Reservations"],
		summary: "Cancel reservation",
		description: "Cancel a reservation"
	}
}).use(requireVendorOrAdmin).patch("/:reservationId/status", async ({ request, params, body }) => {
	const user = await getAuthUser$2(request);
	const validated = updateReservationStatusSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	return success(await updateReservationStatus(params.reservationId, user.id, user.role, validated.data.status), `Status updated to ${validated.data.status}`);
}, {
	params: t.Object({ reservationId: t.String() }),
	body: t.Object({ status: t.Union([
		t.Literal("PENDING"),
		t.Literal("CONFIRMED"),
		t.Literal("PREPARING"),
		t.Literal("READY"),
		t.Literal("COMPLETED"),
		t.Literal("CANCELLED")
	]) }),
	detail: {
		tags: ["Reservations"],
		summary: "Update status",
		description: "Update reservation status"
	}
}).use(requireAdmin).get("/", async ({ query }) => {
	const pagination = paginationSchema.safeParse(query);
	const paginationData = pagination.success ? pagination.data : {
		page: 1,
		limit: 20
	};
	return paginated(await getAllReservations(paginationData, {
		status: query.status,
		vendorId: query.vendorId,
		date: query.date
	}));
}, {
	query: t.Object({
		page: t.Optional(t.String()),
		limit: t.Optional(t.String()),
		status: t.Optional(t.String()),
		vendorId: t.Optional(t.String()),
		date: t.Optional(t.String())
	}),
	detail: {
		tags: ["Reservations"],
		summary: "List all reservations",
		description: "Get all reservations (admin only)"
	}
}).get("/stats/overview", async ({ query }) => {
	return success(await getReservationStats(query.vendorId));
}, {
	query: t.Object({ vendorId: t.Optional(t.String()) }),
	detail: {
		tags: ["Reservations"],
		summary: "Get statistics",
		description: "Get reservation statistics"
	}
});
const vendorReservationsController = new Elysia({ prefix: "/vendors/:vendorId/reservations" }).use(requireAuth).use(requireVendorOrAdmin).get("/", async ({ request, params, query }) => {
	const user = await getAuthUser$2(request);
	const pagination = paginationSchema.safeParse(query);
	const paginationData = pagination.success ? pagination.data : {
		page: 1,
		limit: 20
	};
	return paginated(await getVendorReservations(params.vendorId, user.id, user.role, paginationData, {
		status: query.status,
		date: query.date
	}));
}, {
	params: t.Object({ vendorId: t.String() }),
	query: t.Object({
		page: t.Optional(t.String()),
		limit: t.Optional(t.String()),
		status: t.Optional(t.String()),
		date: t.Optional(t.String())
	}),
	detail: {
		tags: ["Reservations"],
		summary: "Get vendor reservations",
		description: "Get reservations for a vendor"
	}
}).get("/stats", async ({ params }) => {
	return success(await getReservationStats(params.vendorId));
}, {
	params: t.Object({ vendorId: t.String() }),
	detail: {
		tags: ["Reservations"],
		summary: "Get vendor stats",
		description: "Get reservation statistics for a vendor"
	}
});

//#endregion
//#region src/services/timeslot.service.ts
/**
* Create time slot
*/
async function createTimeSlot(vendorId, userId, userRole, input) {
	if (vendorId) {
		const vendor = await prisma.vendor.findUnique({ where: { id: vendorId } });
		if (!vendor) throw new NotFoundError("Vendor");
		if (vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to create time slots for this vendor");
	} else if (userRole !== "ADMIN") throw new ForbiddenError("Only admin can create global time slots");
	return await prisma.timeSlot.create({ data: {
		vendorId,
		label: input.label,
		startTime: input.startTime,
		endTime: input.endTime,
		period: input.period,
		maxOrders: input.maxOrders
	} });
}
/**
* Get time slots (global or vendor-specific)
*/
async function getTimeSlots(vendorId) {
	return await prisma.timeSlot.findMany({
		where: {
			OR: [{ vendorId: null }, { vendorId: vendorId || void 0 }],
			isActive: true
		},
		orderBy: [{ period: "asc" }, { startTime: "asc" }]
	});
}
/**
* Get time slot by ID
*/
async function getTimeSlotById(timeSlotId) {
	const timeSlot = await prisma.timeSlot.findUnique({ where: { id: timeSlotId } });
	if (!timeSlot) throw new NotFoundError("Time slot");
	return timeSlot;
}
/**
* Update time slot
*/
async function updateTimeSlot(timeSlotId, userId, userRole, input) {
	const timeSlot = await prisma.timeSlot.findUnique({
		where: { id: timeSlotId },
		include: { vendor: true }
	});
	if (!timeSlot) throw new NotFoundError("Time slot");
	if (timeSlot.vendor) {
		if (timeSlot.vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to update this time slot");
	} else if (userRole !== "ADMIN") throw new ForbiddenError("Only admin can update global time slots");
	return await prisma.timeSlot.update({
		where: { id: timeSlotId },
		data: {
			label: input.label,
			startTime: input.startTime,
			endTime: input.endTime,
			period: input.period,
			maxOrders: input.maxOrders,
			isActive: input.isActive
		}
	});
}
/**
* Delete time slot
*/
async function deleteTimeSlot(timeSlotId, userId, userRole) {
	const timeSlot = await prisma.timeSlot.findUnique({
		where: { id: timeSlotId },
		include: { vendor: true }
	});
	if (!timeSlot) throw new NotFoundError("Time slot");
	if (timeSlot.vendor) {
		if (timeSlot.vendor.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to delete this time slot");
	} else if (userRole !== "ADMIN") throw new ForbiddenError("Only admin can delete global time slots");
	await prisma.timeSlot.delete({ where: { id: timeSlotId } });
}
/**
* Get available time slots for a vendor (considering capacity)
*/
async function getAvailableTimeSlots(vendorId, date) {
	const startDate = new Date(date);
	startDate.setHours(0, 0, 0, 0);
	const endDate = new Date(date);
	endDate.setHours(23, 59, 59, 999);
	return (await prisma.timeSlot.findMany({
		where: {
			OR: [{ vendorId: null }, { vendorId }],
			isActive: true
		},
		include: { reservations: { where: {
			vendorId,
			createdAt: {
				gte: startDate,
				lte: endDate
			},
			status: { notIn: ["CANCELLED"] }
		} } },
		orderBy: [{ period: "asc" }, { startTime: "asc" }]
	})).map((slot) => ({
		...slot,
		totalReservations: slot.reservations.length,
		availableSlots: slot.maxOrders - slot.reservations.length
	}));
}

//#endregion
//#region src/controllers/timeslot.controller.ts
const timeSlotController = new Elysia({ prefix: "/time-slots" }).use(authPlugin).get("/", async ({ query }) => {
	return success(await getTimeSlots(query.vendorId));
}, {
	query: t.Object({ vendorId: t.Optional(t.String()) }),
	detail: {
		tags: ["Time Slots"],
		summary: "Get time slots",
		description: "Get all active time slots"
	}
}).get("/available", async ({ query }) => {
	if (!query.vendorId || !query.date) throw new BadRequestError("vendorId and date are required");
	return success(await getAvailableTimeSlots(query.vendorId, query.date));
}, {
	query: t.Object({
		vendorId: t.String(),
		date: t.String()
	}),
	detail: {
		tags: ["Time Slots"],
		summary: "Get available slots",
		description: "Get available time slots for a vendor on a specific date"
	}
}).get("/:timeSlotId", async ({ params }) => {
	return success(await getTimeSlotById(params.timeSlotId));
}, {
	params: t.Object({ timeSlotId: t.String() }),
	detail: {
		tags: ["Time Slots"],
		summary: "Get time slot",
		description: "Get time slot details"
	}
}).use(requireAuth).use(requireVendorOrAdmin).post("/", async (ctx) => {
	const { user, body } = ctx;
	const validated = createTimeSlotSchema.safeParse(body);
	if (!validated.success) throw new BadRequestError(validated.error.errors[0].message);
	return success(await createTimeSlot(body.vendorId || null, user.id, user.role, validated.data), "Time slot created");
}, {
	body: t.Object({
		vendorId: t.Optional(t.String()),
		label: t.String(),
		startTime: t.String(),
		endTime: t.String(),
		period: t.Union([t.Literal("MORNING"), t.Literal("AFTERNOON")]),
		maxOrders: t.Optional(t.Number())
	}),
	detail: {
		tags: ["Time Slots"],
		summary: "Create time slot",
		description: "Create a new time slot"
	}
}).patch("/:timeSlotId", async (ctx) => {
	const { user, params, body } = ctx;
	return success(await updateTimeSlot(params.timeSlotId, user.id, user.role, body), "Time slot updated");
}, {
	params: t.Object({ timeSlotId: t.String() }),
	body: t.Object({
		label: t.Optional(t.String()),
		startTime: t.Optional(t.String()),
		endTime: t.Optional(t.String()),
		period: t.Optional(t.Union([t.Literal("MORNING"), t.Literal("AFTERNOON")])),
		maxOrders: t.Optional(t.Number()),
		isActive: t.Optional(t.Boolean())
	}),
	detail: {
		tags: ["Time Slots"],
		summary: "Update time slot",
		description: "Update time slot details"
	}
}).delete("/:timeSlotId", async (ctx) => {
	const { user, params } = ctx;
	await deleteTimeSlot(params.timeSlotId, user.id, user.role);
	return success(null, "Time slot deleted");
}, {
	params: t.Object({ timeSlotId: t.String() }),
	detail: {
		tags: ["Time Slots"],
		summary: "Delete time slot",
		description: "Delete a time slot"
	}
});

//#endregion
//#region src/config/cloudinary.ts
cloudinary.config({
	cloud_name: env.CLOUDINARY_CLOUD_NAME,
	api_key: env.CLOUDINARY_API_KEY,
	api_secret: env.CLOUDINARY_API_SECRET,
	secure: true
});
const folderOptions = {
	avatars: {
		folder: "reservation/avatars",
		transformation: [
			{
				width: 200,
				height: 200,
				crop: "fill",
				gravity: "face"
			},
			{ quality: "auto:good" },
			{ format: "auto" }
		]
	},
	vendors: {
		folder: "reservation/vendors",
		transformation: [
			{
				width: 800,
				height: 600,
				crop: "fill"
			},
			{ quality: "auto:good" },
			{ format: "auto" }
		]
	},
	menus: {
		folder: "reservation/menus",
		transformation: [
			{
				width: 400,
				height: 400,
				crop: "fill"
			},
			{ quality: "auto:good" },
			{ format: "auto" }
		]
	},
	banners: {
		folder: "reservation/banners",
		transformation: [
			{
				width: 1920,
				height: 600,
				crop: "fill"
			},
			{ quality: "auto:good" },
			{ format: "auto" }
		]
	},
	reviews: {
		folder: "reservation/reviews",
		transformation: [
			{
				width: 800,
				height: 800,
				crop: "limit"
			},
			{ quality: "auto:good" },
			{ format: "auto" }
		]
	}
};
/**
* Upload image from base64 or URL
*/
async function uploadImage(file, folder, publicId) {
	const options = {
		...folderOptions[folder],
		resource_type: "image",
		unique_filename: true,
		overwrite: true
	};
	if (publicId) options.public_id = publicId;
	const result = await cloudinary.uploader.upload(file, options);
	return {
		url: result.secure_url,
		publicId: result.public_id,
		format: result.format,
		width: result.width,
		height: result.height,
		bytes: result.bytes
	};
}
/**
* Delete image by public ID
*/
async function deleteImage(publicId) {
	try {
		return (await cloudinary.uploader.destroy(publicId)).result === "ok";
	} catch {
		return false;
	}
}

//#endregion
//#region src/services/upload.service.ts
const typeToFolder = {
	AVATAR: "avatars",
	VENDOR_IMAGE: "vendors",
	MENU_IMAGE: "menus",
	BANNER: "banners",
	REVIEW_IMAGE: "reviews"
};
/**
* Upload file from base64 or URL
*/
async function uploadFile(userId, type, file, originalName) {
	const folder = typeToFolder[type];
	const result = await uploadImage(file, folder);
	return await prisma.upload.create({ data: {
		userId,
		type,
		url: result.url,
		publicId: result.publicId,
		format: result.format,
		width: result.width,
		height: result.height,
		bytes: result.bytes,
		originalName
	} });
}
/**
* Delete upload
*/
async function deleteUpload(uploadId, userId, isAdmin = false) {
	const upload = await prisma.upload.findUnique({ where: { id: uploadId } });
	if (!upload) throw new NotFoundError("Upload");
	if (upload.userId !== userId && !isAdmin) throw new ForbiddenError("Not authorized to delete this upload");
	await deleteImage(upload.publicId);
	await prisma.upload.delete({ where: { id: uploadId } });
}
/**
* Get uploads for a user
*/
async function getUserUploads(userId, type) {
	const where = { userId };
	if (type) where.type = type;
	return prisma.upload.findMany({
		where,
		orderBy: { createdAt: "desc" }
	});
}
/**
* Get upload by ID
*/
async function getUploadById(uploadId) {
	const upload = await prisma.upload.findUnique({ where: { id: uploadId } });
	if (!upload) throw new NotFoundError("Upload");
	return upload;
}
/**
* Upload avatar and update user
*/
async function uploadAvatar(userId, file) {
	const upload = await uploadFile(userId, "AVATAR", file);
	await prisma.user.update({
		where: { id: userId },
		data: { avatar: upload.url }
	});
	return upload;
}
/**
* Upload vendor image and update vendor
*/
async function uploadVendorImage(userId, vendorId, file) {
	const vendor = await prisma.vendor.findUnique({ where: { id: vendorId } });
	if (!vendor) throw new NotFoundError("Vendor");
	if (vendor.userId !== userId) throw new ForbiddenError("Not authorized to update this vendor");
	const upload = await uploadFile(userId, "VENDOR_IMAGE", file);
	await prisma.vendor.update({
		where: { id: vendorId },
		data: { image: upload.url }
	});
	return upload;
}
/**
* Upload menu item image and update menu item
*/
async function uploadMenuItemImage(userId, menuItemId, file) {
	const menuItem = await prisma.menuItem.findUnique({
		where: { id: menuItemId },
		include: { vendor: true }
	});
	if (!menuItem) throw new NotFoundError("Menu item");
	if (menuItem.vendor.userId !== userId) throw new ForbiddenError("Not authorized to update this menu item");
	const upload = await uploadFile(userId, "MENU_IMAGE", file);
	await prisma.menuItem.update({
		where: { id: menuItemId },
		data: { image: upload.url }
	});
	return upload;
}

//#endregion
//#region src/controllers/upload.controller.ts
async function getAuthUser$1(request) {
	const authHeader = request.headers.get("authorization");
	if (!authHeader?.startsWith("Bearer ")) throw new UnauthorizedError("Authentication required");
	const user = await validateSession(authHeader.slice(7));
	if (!user) throw new UnauthorizedError("Invalid or expired session");
	return user;
}
const uploadController = new Elysia({ prefix: "/uploads" }).use(bearer()).post("/", async ({ request, body }) => {
	const user = await getAuthUser$1(request);
	if (!body.file) throw new BadRequestError("File is required");
	return success(await uploadFile(user.id, body.type, body.file, body.originalName), "File uploaded successfully");
}, {
	body: t.Object({
		type: t.Union([
			t.Literal("AVATAR"),
			t.Literal("VENDOR_IMAGE"),
			t.Literal("MENU_IMAGE"),
			t.Literal("BANNER"),
			t.Literal("REVIEW_IMAGE")
		]),
		file: t.String(),
		originalName: t.Optional(t.String())
	}),
	detail: {
		tags: ["Uploads"],
		summary: "Upload file",
		description: "Upload file from base64 or URL"
	}
}).post("/avatar", async ({ request, body }) => {
	const user = await getAuthUser$1(request);
	if (!body.file) throw new BadRequestError("File is required");
	return success(await uploadAvatar(user.id, body.file), "Avatar uploaded successfully");
}, {
	body: t.Object({ file: t.String() }),
	detail: {
		tags: ["Uploads"],
		summary: "Upload avatar",
		description: "Upload user avatar"
	}
}).post("/vendor/:vendorId", async ({ request, params, body }) => {
	const user = await getAuthUser$1(request);
	if (!body.file) throw new BadRequestError("File is required");
	return success(await uploadVendorImage(user.id, params.vendorId, body.file), "Vendor image uploaded successfully");
}, {
	params: t.Object({ vendorId: t.String() }),
	body: t.Object({ file: t.String() }),
	detail: {
		tags: ["Uploads"],
		summary: "Upload vendor image",
		description: "Upload vendor shop image"
	}
}).post("/menu/:menuItemId", async ({ request, params, body }) => {
	const user = await getAuthUser$1(request);
	if (!body.file) throw new BadRequestError("File is required");
	return success(await uploadMenuItemImage(user.id, params.menuItemId, body.file), "Menu item image uploaded successfully");
}, {
	params: t.Object({ menuItemId: t.String() }),
	body: t.Object({ file: t.String() }),
	detail: {
		tags: ["Uploads"],
		summary: "Upload menu image",
		description: "Upload menu item image"
	}
}).get("/me", async ({ request, query }) => {
	const user = await getAuthUser$1(request);
	return success(await getUserUploads(user.id, query.type));
}, {
	query: t.Object({ type: t.Optional(t.String()) }),
	detail: {
		tags: ["Uploads"],
		summary: "Get my uploads",
		description: "Get current user uploads"
	}
}).get("/:uploadId", async ({ params }) => {
	return success(await getUploadById(params.uploadId));
}, {
	params: t.Object({ uploadId: t.String() }),
	detail: {
		tags: ["Uploads"],
		summary: "Get upload",
		description: "Get upload details"
	}
}).delete("/:uploadId", async ({ request, params }) => {
	const user = await getAuthUser$1(request);
	await deleteUpload(params.uploadId, user.id, user.role === "ADMIN");
	return success(null, "Upload deleted");
}, {
	params: t.Object({ uploadId: t.String() }),
	detail: {
		tags: ["Uploads"],
		summary: "Delete upload",
		description: "Delete an upload"
	}
});

//#endregion
//#region src/services/review.service.ts
/**
* Create a new review
*/
async function createReview(userId, input) {
	if (input.rating < 1 || input.rating > 5) throw new BadRequestError("Rating must be between 1 and 5");
	if (!await prisma.vendor.findUnique({ where: { id: input.vendorId } })) throw new NotFoundError("Vendor");
	if (!await prisma.reservation.findFirst({ where: {
		customerId: userId,
		vendorId: input.vendorId,
		status: "COMPLETED"
	} })) throw new BadRequestError("You can only review vendors you have ordered from");
	if (await prisma.review.findFirst({ where: {
		userId,
		vendorId: input.vendorId
	} })) throw new BadRequestError("You have already reviewed this vendor");
	const review = await prisma.review.create({
		data: {
			userId,
			vendorId: input.vendorId,
			rating: input.rating,
			comment: input.comment,
			images: input.images || []
		},
		include: {
			user: { select: {
				id: true,
				name: true,
				avatar: true
			} },
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} }
		}
	});
	await updateVendorRating(input.vendorId);
	return review;
}
/**
* Update an existing review
*/
async function updateReview(reviewId, userId, userRole, input) {
	const review = await prisma.review.findUnique({ where: { id: reviewId } });
	if (!review) throw new NotFoundError("Review");
	if (review.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to update this review");
	if (input.rating !== void 0 && (input.rating < 1 || input.rating > 5)) throw new BadRequestError("Rating must be between 1 and 5");
	const updated = await prisma.review.update({
		where: { id: reviewId },
		data: {
			rating: input.rating,
			comment: input.comment,
			images: input.images
		},
		include: {
			user: { select: {
				id: true,
				name: true,
				avatar: true
			} },
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} }
		}
	});
	if (input.rating !== void 0) await updateVendorRating(review.vendorId);
	return updated;
}
/**
* Delete a review
*/
async function deleteReview(reviewId, userId, userRole) {
	const review = await prisma.review.findUnique({ where: { id: reviewId } });
	if (!review) throw new NotFoundError("Review");
	if (review.userId !== userId && userRole !== "ADMIN") throw new ForbiddenError("Not authorized to delete this review");
	await prisma.review.delete({ where: { id: reviewId } });
	await updateVendorRating(review.vendorId);
}
/**
* Get review by ID
*/
async function getReviewById(reviewId) {
	const review = await prisma.review.findUnique({
		where: { id: reviewId },
		include: {
			user: { select: {
				id: true,
				name: true,
				avatar: true
			} },
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} }
		}
	});
	if (!review) throw new NotFoundError("Review");
	return review;
}
/**
* Get reviews for a vendor
*/
async function getVendorReviews(vendorId, pagination, filters) {
	const { page, limit, skip } = parsePagination(pagination);
	const where = { vendorId };
	if (filters?.rating) where.rating = filters.rating;
	let orderBy = { createdAt: "desc" };
	if (filters?.sortBy === "oldest") orderBy = { createdAt: "asc" };
	else if (filters?.sortBy === "highest") orderBy = { rating: "desc" };
	else if (filters?.sortBy === "lowest") orderBy = { rating: "asc" };
	const [reviews, total] = await Promise.all([prisma.review.findMany({
		where,
		include: { user: { select: {
			id: true,
			name: true,
			avatar: true
		} } },
		orderBy,
		skip,
		take: limit
	}), prisma.review.count({ where })]);
	return {
		items: reviews,
		meta: createPaginationMeta(page, limit, total)
	};
}
/**
* Get user's reviews
*/
async function getUserReviews(userId, pagination) {
	const { page, limit, skip } = parsePagination(pagination);
	const [reviews, total] = await Promise.all([prisma.review.findMany({
		where: { userId },
		include: { vendor: { select: {
			id: true,
			name: true,
			image: true
		} } },
		orderBy: { createdAt: "desc" },
		skip,
		take: limit
	}), prisma.review.count({ where: { userId } })]);
	return {
		items: reviews,
		meta: createPaginationMeta(page, limit, total)
	};
}
/**
* Get all reviews (admin)
*/
async function getAllReviews(pagination, filters) {
	const { page, limit, skip } = parsePagination(pagination);
	const where = {};
	if (filters?.vendorId) where.vendorId = filters.vendorId;
	if (filters?.userId) where.userId = filters.userId;
	if (filters?.rating) where.rating = filters.rating;
	const [reviews, total] = await Promise.all([prisma.review.findMany({
		where,
		include: {
			user: { select: {
				id: true,
				name: true,
				avatar: true
			} },
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} }
		},
		orderBy: { createdAt: "desc" },
		skip,
		take: limit
	}), prisma.review.count({ where })]);
	return {
		items: reviews,
		meta: createPaginationMeta(page, limit, total)
	};
}
/**
* Get review statistics for a vendor
*/
async function getVendorReviewStats(vendorId) {
	const reviews = await prisma.review.findMany({
		where: { vendorId },
		select: { rating: true }
	});
	const totalReviews = reviews.length;
	if (totalReviews === 0) return {
		averageRating: 0,
		totalReviews: 0,
		ratingDistribution: {
			1: 0,
			2: 0,
			3: 0,
			4: 0,
			5: 0
		}
	};
	const ratingSum = reviews.reduce((sum, r) => sum + r.rating, 0);
	return {
		averageRating: Math.round(ratingSum / totalReviews * 10) / 10,
		totalReviews,
		ratingDistribution: {
			1: reviews.filter((r) => r.rating === 1).length,
			2: reviews.filter((r) => r.rating === 2).length,
			3: reviews.filter((r) => r.rating === 3).length,
			4: reviews.filter((r) => r.rating === 4).length,
			5: reviews.filter((r) => r.rating === 5).length
		}
	};
}
/**
* Get recent reviews (for homepage)
*/
async function getRecentReviews(limit = 10) {
	return await prisma.review.findMany({
		where: { rating: { gte: 4 } },
		include: {
			user: { select: {
				id: true,
				name: true,
				avatar: true
			} },
			vendor: { select: {
				id: true,
				name: true,
				image: true
			} }
		},
		orderBy: { createdAt: "desc" },
		take: limit
	});
}
/**
* Check if user can review a vendor
*/
async function canUserReviewVendor(userId, vendorId) {
	if (!await prisma.reservation.findFirst({ where: {
		customerId: userId,
		vendorId,
		status: "COMPLETED"
	} })) return {
		canReview: false,
		reason: "You need to complete an order before reviewing"
	};
	if (await prisma.review.findFirst({ where: {
		userId,
		vendorId
	} })) return {
		canReview: false,
		reason: "You have already reviewed this vendor"
	};
	return { canReview: true };
}
/**
* Update vendor's average rating
*/
async function updateVendorRating(vendorId) {
	const stats = await getVendorReviewStats(vendorId);
	await prisma.vendor.update({
		where: { id: vendorId },
		data: { rating: stats.averageRating }
	});
}
/**
* Get top rated vendors
*/
async function getTopRatedVendors(limit = 5) {
	return (await prisma.vendor.findMany({
		where: {
			isOpen: true,
			rating: { gt: 0 }
		},
		include: { _count: { select: { reviews: true } } },
		orderBy: [{ rating: "desc" }, { totalOrders: "desc" }],
		take: limit
	})).map((v) => ({
		id: v.id,
		name: v.name,
		image: v.image,
		rating: v.rating,
		totalReviews: v._count.reviews,
		totalOrders: v.totalOrders
	}));
}

//#endregion
//#region src/controllers/review.controller.ts
async function getAuthUser(request) {
	const authHeader = request.headers.get("authorization");
	if (!authHeader?.startsWith("Bearer ")) throw new UnauthorizedError("Authentication required");
	const user = await validateSession(authHeader.slice(7));
	if (!user) throw new UnauthorizedError("Invalid or expired session");
	return user;
}
const reviewController = new Elysia({ prefix: "/reviews" }).use(bearer()).get("/recent", async ({ query }) => {
	const limit = query.limit ? parseInt(query.limit) : 10;
	return success(await getRecentReviews(limit));
}, {
	query: t.Object({ limit: t.Optional(t.String()) }),
	detail: {
		tags: ["Reviews"],
		summary: "Get recent reviews",
		description: "Get recent positive reviews for homepage"
	}
}).get("/top-vendors", async ({ query }) => {
	const limit = query.limit ? parseInt(query.limit) : 5;
	return success(await getTopRatedVendors(limit));
}, {
	query: t.Object({ limit: t.Optional(t.String()) }),
	detail: {
		tags: ["Reviews"],
		summary: "Get top rated vendors",
		description: "Get vendors with highest ratings"
	}
}).get("/:reviewId", async ({ params }) => {
	return success(await getReviewById(params.reviewId));
}, {
	params: t.Object({ reviewId: t.String() }),
	detail: {
		tags: ["Reviews"],
		summary: "Get review",
		description: "Get review details"
	}
}).post("/", async ({ request, body }) => {
	const user = await getAuthUser(request);
	if (!body.vendorId || !body.rating) throw new BadRequestError("Vendor ID and rating are required");
	return success(await createReview(user.id, {
		vendorId: body.vendorId,
		rating: body.rating,
		comment: body.comment,
		images: body.images
	}), "Review created successfully");
}, {
	body: t.Object({
		vendorId: t.String(),
		rating: t.Number({
			minimum: 1,
			maximum: 5
		}),
		comment: t.Optional(t.String()),
		images: t.Optional(t.Array(t.String()))
	}),
	detail: {
		tags: ["Reviews"],
		summary: "Create review",
		description: "Create a new review for a vendor"
	}
}).patch("/:reviewId", async ({ request, params, body }) => {
	const user = await getAuthUser(request);
	return success(await updateReview(params.reviewId, user.id, user.role, body), "Review updated successfully");
}, {
	params: t.Object({ reviewId: t.String() }),
	body: t.Object({
		rating: t.Optional(t.Number({
			minimum: 1,
			maximum: 5
		})),
		comment: t.Optional(t.String()),
		images: t.Optional(t.Array(t.String()))
	}),
	detail: {
		tags: ["Reviews"],
		summary: "Update review",
		description: "Update an existing review"
	}
}).delete("/:reviewId", async ({ request, params }) => {
	const user = await getAuthUser(request);
	await deleteReview(params.reviewId, user.id, user.role);
	return success(null, "Review deleted successfully");
}, {
	params: t.Object({ reviewId: t.String() }),
	detail: {
		tags: ["Reviews"],
		summary: "Delete review",
		description: "Delete a review"
	}
}).get("/me", async ({ request, query }) => {
	const user = await getAuthUser(request);
	const pagination = paginationSchema.safeParse(query);
	const paginationData = pagination.success ? pagination.data : {
		page: 1,
		limit: 20
	};
	return paginated(await getUserReviews(user.id, paginationData));
}, {
	query: t.Object({
		page: t.Optional(t.String()),
		limit: t.Optional(t.String())
	}),
	detail: {
		tags: ["Reviews"],
		summary: "Get my reviews",
		description: "Get current user reviews"
	}
}).get("/can-review/:vendorId", async ({ request, params }) => {
	const user = await getAuthUser(request);
	return success(await canUserReviewVendor(user.id, params.vendorId));
}, {
	params: t.Object({ vendorId: t.String() }),
	detail: {
		tags: ["Reviews"],
		summary: "Check if can review",
		description: "Check if current user can review a vendor"
	}
}).use(requireAdmin).get("/", async ({ query }) => {
	const pagination = paginationSchema.safeParse(query);
	const paginationData = pagination.success ? pagination.data : {
		page: 1,
		limit: 20
	};
	return paginated(await getAllReviews(paginationData, {
		vendorId: query.vendorId,
		userId: query.userId,
		rating: query.rating ? parseInt(query.rating) : void 0
	}));
}, {
	query: t.Object({
		page: t.Optional(t.String()),
		limit: t.Optional(t.String()),
		vendorId: t.Optional(t.String()),
		userId: t.Optional(t.String()),
		rating: t.Optional(t.String())
	}),
	detail: {
		tags: ["Reviews"],
		summary: "Get all reviews",
		description: "Get all reviews (admin only)"
	}
});
const vendorReviewsController = new Elysia({ prefix: "/vendors/:vendorId/reviews" }).use(bearer()).get("/", async ({ params, query }) => {
	const pagination = paginationSchema.safeParse(query);
	const paginationData = pagination.success ? pagination.data : {
		page: 1,
		limit: 20
	};
	return paginated(await getVendorReviews(params.vendorId, paginationData, {
		rating: query.rating ? parseInt(query.rating) : void 0,
		sortBy: query.sortBy
	}));
}, {
	params: t.Object({ vendorId: t.String() }),
	query: t.Object({
		page: t.Optional(t.String()),
		limit: t.Optional(t.String()),
		rating: t.Optional(t.String()),
		sortBy: t.Optional(t.String())
	}),
	detail: {
		tags: ["Reviews"],
		summary: "Get vendor reviews",
		description: "Get all reviews for a vendor"
	}
}).get("/stats", async ({ params }) => {
	return success(await getVendorReviewStats(params.vendorId));
}, {
	params: t.Object({ vendorId: t.String() }),
	detail: {
		tags: ["Reviews"],
		summary: "Get vendor review stats",
		description: "Get review statistics for a vendor"
	}
});

//#endregion
//#region src/index.ts
const PORT = Number(process.env.PORT) || 3002;
const NODE_ENV = process.env.NODE_ENV || "development";
const FRONTEND_URL = process.env.FRONTEND_URL || "http://localhost:3000";
new Elysia().onError(({ code, error, set }) => {
	console.error(`[Error] ${code}:`, error);
	if (error instanceof AppError) {
		set.status = error.statusCode;
		return formatErrorResponse(error);
	}
	if (code === "VALIDATION") {
		set.status = 400;
		return {
			success: false,
			error: "Validation failed",
			code: "VALIDATION_ERROR",
			details: error.message
		};
	}
	if (code === "NOT_FOUND") {
		set.status = 404;
		return {
			success: false,
			error: "Route not found",
			code: "NOT_FOUND"
		};
	}
	set.status = getErrorStatusCode(error);
	return formatErrorResponse(error);
}).use(cors({
	origin: NODE_ENV === "production" ? FRONTEND_URL : ["http://localhost:3000", `http://localhost:${PORT}`],
	credentials: true,
	allowedHeaders: [
		"Content-Type",
		"Authorization",
		"X-API-Key",
		"X-Requested-With"
	],
	methods: [
		"GET",
		"POST",
		"PUT",
		"PATCH",
		"DELETE",
		"OPTIONS"
	]
})).use(logixlysia({ config: {
	showStartupMessage: true,
	startupMessageFormat: "banner",
	timestamp: { translateTime: "yyyy-mm-dd HH:MM:ss" },
	ip: true,
	customLogFormat: "🦊 {now} {level} {duration} {method} {pathname} {status}"
} })).use(openapi({ path: "/docs" })).get("/health", () => ({
	success: true,
	data: {
		status: "healthy",
		timestamp: (/* @__PURE__ */ new Date()).toISOString(),
		version: "1.0.0"
	}
})).group("/api", (app) => app.use(authController).use(passwordResetController).use(userController).use(apiKeyController).use(vendorController).use(menuController).use(vendorMenuController).use(reservationController).use(vendorReservationsController).use(timeSlotController).use(uploadController).use(reviewController).use(vendorReviewsController)).all("*", ({ set }) => {
	set.status = 404;
	return {
		success: false,
		error: "Endpoint not found",
		code: "NOT_FOUND"
	};
}, { detail: { hide: true } });

//#endregion
export { sendOrderConfirmedEmail as a, sendPasswordResetEmail as c, sendOrderCompletedEmail as i, sendTestEmail as l, sendEmail as n, sendOrderPreparingEmail as o, sendOrderCancelledEmail as r, sendOrderReadyEmail as s, sendAccountLockedEmail as t, sendVerificationEmail as u };
//# sourceMappingURL=index.mjs.map