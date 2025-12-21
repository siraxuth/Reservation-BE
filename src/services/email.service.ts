// Email Service
// Handles sending emails for verification, password reset, etc.
// Optimized for Gmail SMTP with anti-spam best practices

import nodemailer from 'nodemailer';
import { env } from '../config/env';
import { randomUUID } from 'crypto';

interface EmailOptions {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

// Create reusable transporter
let transporter: nodemailer.Transporter | null = null;

// Get the sender email - for Gmail, must match SMTP_USER
function getSenderEmail(): string {
  // Gmail requires the from address to match the authenticated user
  // or be an alias configured in Gmail settings
  if (env.SMTP_HOST === 'smtp.gmail.com') {
    return env.SMTP_USER || env.SMTP_FROM || 'noreply@example.com';
  }
  return env.SMTP_FROM || env.SMTP_USER || 'noreply@example.com';
}

function getTransporter(): nodemailer.Transporter | null {
  if (transporter) return transporter;

  // Check if SMTP is configured
  if (!env.SMTP_HOST || !env.SMTP_USER || !env.SMTP_PASS) {
    return null;
  }

  // Gmail-specific configuration for reliable delivery
  const isGmail = env.SMTP_HOST === 'smtp.gmail.com';

  transporter = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: env.SMTP_PORT,
    secure: env.SMTP_SECURE, // true for 465, false for other ports
    auth: {
      user: env.SMTP_USER,
      pass: env.SMTP_PASS,
    },
    // Connection pool for better performance
    pool: true,
    maxConnections: 5,
    maxMessages: 100,
    // Gmail-specific settings
    ...(isGmail && {
      // Increase timeouts for Gmail
      connectionTimeout: 10000,
      greetingTimeout: 10000,
      socketTimeout: 15000,
    }),
    // TLS settings
    tls: {
      rejectUnauthorized: true,
      minVersion: 'TLSv1.2',
    },
  });

  // Verify connection on startup
  transporter.verify((error) => {
    if (error) {
      console.error('[Email Service] SMTP connection failed:', error.message);
    } else {
      console.log('[Email Service] SMTP server is ready to send emails');
    }
  });

  return transporter;
}

/**
 * Generate a unique Message-ID for email tracking
 */
function generateMessageId(): string {
  const domain = getSenderEmail().split('@')[1] || 'foodqueue.local';
  return `<${randomUUID()}@${domain}>`;
}

/**
 * Send an email
 * In development without SMTP config, logs to console instead
 * Includes anti-spam headers for better deliverability
 */
export async function sendEmail(options: EmailOptions): Promise<boolean> {
  const transport = getTransporter();
  const senderEmail = getSenderEmail();
  const senderName = 'Food Queue Reservation';

  // If no SMTP configured, log to console (development mode)
  if (!transport) {
    console.log('\n[Email Service - No SMTP Configured]');
    console.log(`To: ${options.to}`);
    console.log(`Subject: ${options.subject}`);
    console.log(`Body:\n${options.text || options.html}\n`);
    return true; // Return success for development
  }

  try {
    const messageId = generateMessageId();

    await transport.sendMail({
      // From with display name - improves trust
      from: `"${senderName}" <${senderEmail}>`,
      to: options.to,
      subject: options.subject,
      html: options.html,
      text: options.text,
      // Important headers for anti-spam
      messageId: messageId,
      headers: {
        // Precedence header to indicate transactional email
        'Precedence': 'bulk',
        // Auto-submitted header to indicate automated email
        'Auto-Submitted': 'auto-generated',
        // X-Mailer to identify the sending application
        'X-Mailer': 'Food Queue Reservation System',
        // List-Unsubscribe header (recommended for better deliverability)
        'List-Unsubscribe': `<mailto:${senderEmail}?subject=unsubscribe>`,
      },
      // Reply-to same as sender for consistency
      replyTo: senderEmail,
    });

    console.log(`[Email Service] Email sent successfully to ${options.to}`);
    return true;
  } catch (error) {
    console.error('[Email Service] Failed to send email:', error);
    return false;
  }
}

/**
 * Send email verification link
 */
export async function sendVerificationEmail(
  email: string,
  name: string,
  token: string
): Promise<boolean> {
  const verifyUrl = `${env.FRONTEND_URL}/verify-email?token=${token}`;
  const currentYear = new Date().getFullYear();

  return sendEmail({
    to: email,
    subject: 'ยืนยันอีเมลของคุณ - ระบบจองคิวอาหาร',
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
    text: `สวัสดีคุณ ${name},\n\nขอบคุณที่ลงทะเบียนกับระบบจองคิวอาหาร!\n\nกรุณายืนยันอีเมลของคุณโดยคลิกลิงก์:\n${verifyUrl}\n\nลิงก์นี้จะหมดอายุใน ${env.EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS} ชั่วโมง\n\nหากคุณไม่ได้สร้างบัญชีนี้ กรุณาเพิกเฉยอีเมลนี้\n\n---\nระบบจองคิวอาหาร`,
  });
}

/**
 * Send password reset link
 */
export async function sendPasswordResetEmail(
  email: string,
  name: string,
  token: string
): Promise<boolean> {
  const resetUrl = `${env.FRONTEND_URL}/reset-password?token=${token}`;
  const currentYear = new Date().getFullYear();

  return sendEmail({
    to: email,
    subject: 'รีเซ็ตรหัสผ่าน - ระบบจองคิวอาหาร',
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
    text: `สวัสดีคุณ ${name},\n\nเราได้รับคำขอรีเซ็ตรหัสผ่านของคุณ\n\nคลิกลิงก์นี้เพื่อสร้างรหัสผ่านใหม่:\n${resetUrl}\n\nลิงก์นี้จะหมดอายุใน ${env.PASSWORD_RESET_TOKEN_EXPIRES_HOURS} ชั่วโมง\n\nหากคุณไม่ได้ขอรีเซ็ตรหัสผ่าน กรุณาเพิกเฉยอีเมลนี้\n\n---\nระบบจองคิวอาหาร`,
  });
}

/**
 * Send account locked notification
 */
/**
 * Send a test email to verify SMTP configuration
 */
export async function sendTestEmail(email: string): Promise<{ success: boolean; message: string }> {
  const transport = getTransporter();
  const senderEmail = getSenderEmail();
  const currentYear = new Date().getFullYear();

  if (!transport) {
    return {
      success: false,
      message: 'SMTP not configured. Please set SMTP_HOST, SMTP_USER, and SMTP_PASS in .env file.',
    };
  }

  try {
    const result = await transport.sendMail({
      from: `"Food Queue Reservation" <${senderEmail}>`,
      to: email,
      subject: '✅ ทดสอบระบบอีเมล - ระบบจองคิวอาหาร',
      messageId: generateMessageId(),
      headers: {
        'Precedence': 'bulk',
        'Auto-Submitted': 'auto-generated',
        'X-Mailer': 'Food Queue Reservation System',
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
                      <p style="margin: 0 0 20px; color: #4b5563; font-size: 14px;">เวลา: <strong>${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}</strong></p>
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
      text: `ทดสอบระบบอีเมลสำเร็จ!\n\nอีเมลนี้ถูกส่งเพื่อทดสอบการตั้งค่า SMTP\nส่งจาก: ${senderEmail}\nเวลา: ${new Date().toLocaleString('th-TH', { timeZone: 'Asia/Bangkok' })}\n\nระบบอีเมลของคุณพร้อมใช้งานแล้ว!`,
    });

    console.log('[Email Service] Test email sent successfully:', result.messageId);
    return {
      success: true,
      message: `Test email sent successfully to ${email}. Message ID: ${result.messageId}`,
    };
  } catch (error: any) {
    console.error('[Email Service] Test email failed:', error);
    return {
      success: false,
      message: `Failed to send test email: ${error.message || 'Unknown error'}`,
    };
  }
}

// ===================================================
// Order Status Notification Emails
// ===================================================

interface OrderDetails {
  queueNumber: number;
  vendorName: string;
  customerName: string;
  items: { name: string; quantity: number; price: number }[];
  totalAmount: number;
  timeSlot?: string;
}

/**
 * Generate order items table HTML
 */
function generateOrderItemsHtml(items: OrderDetails['items']): string {
  return items.map(item => `
    <tr>
      <td style="padding: 10px 15px; border-bottom: 1px solid #e5e7eb;">${item.name}</td>
      <td style="padding: 10px 15px; border-bottom: 1px solid #e5e7eb; text-align: center;">${item.quantity}</td>
      <td style="padding: 10px 15px; border-bottom: 1px solid #e5e7eb; text-align: right;">฿${(item.price * item.quantity).toLocaleString()}</td>
    </tr>
  `).join('');
}

/**
 * Send order confirmed email
 */
export async function sendOrderConfirmedEmail(
  email: string,
  order: OrderDetails
): Promise<boolean> {
  const currentYear = new Date().getFullYear();

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
                    ` : ''}

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
    text: `ยืนยันคำสั่งซื้อแล้ว!\n\nหมายเลขคิว: #${order.queueNumber}\nร้าน: ${order.vendorName}\n${order.timeSlot ? `ช่วงเวลารับ: ${order.timeSlot}\n` : ''}\nรวมทั้งหมด: ฿${order.totalAmount.toLocaleString()}\n\nกรุณารอการเตรียมอาหาร`,
  });
}

/**
 * Send order preparing email
 */
export async function sendOrderPreparingEmail(
  email: string,
  order: OrderDetails
): Promise<boolean> {
  const currentYear = new Date().getFullYear();

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
    text: `กำลังเตรียมอาหาร!\n\nหมายเลขคิว: #${order.queueNumber}\nร้าน: ${order.vendorName}\n\nร้านค้าเริ่มเตรียมออเดอร์ของคุณแล้ว คุณจะได้รับแจ้งเตือนเมื่อพร้อมรับ`,
  });
}

/**
 * Send order ready email
 */
export async function sendOrderReadyEmail(
  email: string,
  order: OrderDetails
): Promise<boolean> {
  const currentYear = new Date().getFullYear();

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
    text: `🎉 ออเดอร์พร้อมรับแล้ว!\n\nหมายเลขคิว: #${order.queueNumber}\nร้าน: ${order.vendorName}\n\nอาหารของคุณพร้อมแล้ว! กรุณามารับที่ร้าน\nแสดงหมายเลขคิว #${order.queueNumber} เพื่อรับอาหาร`,
  });
}

/**
 * Send order completed email with review reminder
 */
export async function sendOrderCompletedEmail(
  email: string,
  order: OrderDetails,
  reviewUrl?: string
): Promise<boolean> {
  const currentYear = new Date().getFullYear();
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
    text: `🙏 ขอบคุณที่ใช้บริการ!\n\nร้าน: ${order.vendorName}\nออเดอร์: #${order.queueNumber}\nยอดรวม: ฿${order.totalAmount.toLocaleString()}\n\n⭐ รีวิวร้านค้า: ${reviewUrl || defaultReviewUrl}\n\nหวังว่าจะได้พบคุณอีกครั้ง!`,
  });
}

/**
 * Send order cancelled email
 */
export async function sendOrderCancelledEmail(
  email: string,
  order: OrderDetails,
  reason?: string
): Promise<boolean> {
  const currentYear = new Date().getFullYear();

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
                    ` : ''}

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
    text: `❌ คำสั่งซื้อถูกยกเลิก\n\nหมายเลขคิว: #${order.queueNumber}\nร้าน: ${order.vendorName}\n${reason ? `เหตุผล: ${reason}\n` : ''}\nยอดที่ถูกยกเลิก: ฿${order.totalAmount.toLocaleString()}`,
  });
}

export async function sendAccountLockedEmail(
  email: string,
  name: string,
  lockedUntil: Date
): Promise<boolean> {
  const unlockTime = lockedUntil.toLocaleString('th-TH', {
    timeZone: 'Asia/Bangkok',
    dateStyle: 'medium',
    timeStyle: 'short',
  });
  const currentYear = new Date().getFullYear();

  return sendEmail({
    to: email,
    subject: '🚨 แจ้งเตือนความปลอดภัย - บัญชีถูกล็อคชั่วคราว',
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
    text: `สวัสดีคุณ ${name},\n\n⚠️ บัญชีของคุณถูกล็อคชั่วคราว\n\nเนื่องจากมีการพยายามเข้าสู่ระบบด้วยรหัสผ่านผิดหลายครั้ง\n\nบัญชีของคุณจะถูกปลดล็อคอัตโนมัติในเวลา: ${unlockTime}\n\nหากไม่ใช่คุณที่พยายามเข้าสู่ระบบ กรุณารีเซ็ตรหัสผ่านทันทีหลังจากบัญชีถูกปลดล็อค\n\n---\nระบบจองคิวอาหาร`,
  });
}
