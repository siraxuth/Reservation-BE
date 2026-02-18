// Environment Configuration
// Validates and exports all environment variables with production security checks

// List of insecure default values that must not be used in production
const INSECURE_JWT_SECRETS = [
  "dev-secret-key-change-in-production",
  "secret",
  "jwt-secret",
  "changeme",
  "password",
  "123456",
];

const getEnv = (key: string, defaultValue?: string): string => {
  const value = process.env[key] || defaultValue;
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
};

// Get optional environment variable (allows empty string)
const getEnvOptional = (key: string, defaultValue: string = ""): string => {
  const value = process.env[key];
  return value !== undefined ? value : defaultValue;
};

const getEnvNumber = (key: string, defaultValue?: number): number => {
  const value = process.env[key];
  if (value) return parseInt(value, 10);
  if (defaultValue !== undefined) return defaultValue;
  throw new Error(`Missing required environment variable: ${key}`);
};

const getEnvBoolean = (key: string, defaultValue: boolean = false): boolean => {
  const value = process.env[key];
  if (value === undefined) return defaultValue;
  return value.toLowerCase() === "true";
};

// Production security validation
function validateProductionSecurity(): void {
  const isProduction = getEnv("NODE_ENV", "development") === "production";

  if (!isProduction) {
    console.warn(
      "\n[Security] Running in development mode - security checks relaxed\n",
    );
    return;
  }

  const errors: string[] = [];
  const warnings: string[] = [];

  // Validate JWT_SECRET
  const jwtSecret = process.env.JWT_SECRET;
  if (!jwtSecret) {
    errors.push("JWT_SECRET is required in production");
  } else {
    // Check against insecure defaults
    if (INSECURE_JWT_SECRETS.includes(jwtSecret.toLowerCase())) {
      errors.push(
        "JWT_SECRET is using an insecure default value - please set a secure secret",
      );
    }

    // Check minimum length (32 characters)
    if (jwtSecret.length < 32) {
      errors.push("JWT_SECRET must be at least 32 characters long");
    }

    // Check entropy (basic check)
    const uniqueChars = new Set(jwtSecret).size;
    if (uniqueChars < 10) {
      warnings.push(
        "JWT_SECRET has low character variety - consider using a more random value",
      );
    }
  }

  // Validate FRONTEND_URL
  const frontendUrl = process.env.FRONTEND_URL;
  if (!frontendUrl || frontendUrl.includes("localhost")) {
    errors.push("FRONTEND_URL must be set to production URL (not localhost)");
  }

  // Validate DATABASE_URL
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    errors.push("DATABASE_URL is required");
  }

  // Check SMTP for email features
  if (!process.env.SMTP_HOST) {
    warnings.push("SMTP_HOST not configured - email features will not work");
  }

  // Print warnings
  if (warnings.length > 0) {
    console.warn("\n[Production Security Warnings]");
    warnings.forEach((w) => console.warn(`  - ${w}`));
  }

  // Throw errors if any critical issues
  if (errors.length > 0) {
    console.error("\n[CRITICAL: Production Security Errors]");
    errors.forEach((e) => console.error(`  - ${e}`));
    console.error("\nApplication cannot start with insecure configuration.");
    console.error(
      "Please fix the above issues before deploying to production.\n",
    );
    process.exit(1);
  }

  console.log("[Security] Production security validation passed\n");
}

// Run validation on module load
validateProductionSecurity();

export const env = {
  // Server
  PORT: getEnvNumber("PORT", 3001),
  NODE_ENV: getEnv("NODE_ENV", "development"),
  IS_PRODUCTION: getEnv("NODE_ENV", "development") === "production",

  // Database
  DATABASE_URL: getEnv("DATABASE_URL"),

  // JWT - No insecure defaults in production (checked above)
  JWT_SECRET: getEnv("JWT_SECRET", "dev-secret-key-change-in-production"),
  JWT_EXPIRES_IN: getEnv("JWT_EXPIRES_IN", "7d"),

  // Google OAuth (optional)
  GOOGLE_CLIENT_ID: getEnvOptional("GOOGLE_CLIENT_ID"),
  GOOGLE_CLIENT_SECRET: getEnvOptional("GOOGLE_CLIENT_SECRET"),
  GOOGLE_CALLBACK_URL: getEnvOptional(
    "GOOGLE_CALLBACK_URL",
    "http://localhost:3001/api/auth/google/callback",
  ),

  // Cloudinary (optional)
  CLOUDINARY_CLOUD_NAME: getEnvOptional("CLOUDINARY_CLOUD_NAME"),
  CLOUDINARY_API_KEY: getEnvOptional("CLOUDINARY_API_KEY"),
  CLOUDINARY_API_SECRET: getEnvOptional("CLOUDINARY_API_SECRET"),

  // Frontend
  FRONTEND_URL: getEnv("FRONTEND_URL", "http://localhost:3000"),

  // API Key
  API_KEY_PREFIX: getEnv("API_KEY_PREFIX", "rk_"),
  API_KEY_LENGTH: getEnvNumber("API_KEY_LENGTH", 32),

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: getEnvNumber("RATE_LIMIT_WINDOW_MS", 60000),
  RATE_LIMIT_MAX_REQUESTS: getEnvNumber("RATE_LIMIT_MAX_REQUESTS", 100),

  // Logging
  LOG_LEVEL: getEnv("LOG_LEVEL", "info"),

  // Account Security
  ACCOUNT_LOCKOUT_THRESHOLD: getEnvNumber("ACCOUNT_LOCKOUT_THRESHOLD", 5),
  ACCOUNT_LOCKOUT_DURATION_MINUTES: getEnvNumber(
    "ACCOUNT_LOCKOUT_DURATION_MINUTES",
    30,
  ),

  // Token Expiry
  PASSWORD_RESET_TOKEN_EXPIRES_HOURS: getEnvNumber(
    "PASSWORD_RESET_TOKEN_EXPIRES_HOURS",
    1,
  ),
  EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS: getEnvNumber(
    "EMAIL_VERIFICATION_TOKEN_EXPIRES_HOURS",
    24,
  ),

  // SMTP Email (optional - if not configured, emails are logged to console)
  SMTP_HOST: getEnvOptional("SMTP_HOST"),
  SMTP_PORT: getEnvNumber("SMTP_PORT", 587),
  SMTP_USER: getEnvOptional("SMTP_USER"),
  SMTP_PASS: getEnvOptional("SMTP_PASS"),
  SMTP_FROM: getEnvOptional("SMTP_FROM", "noreply@example.com"),
  SMTP_SECURE: getEnvBoolean("SMTP_SECURE", false),

  // Firebase Cloud Messaging (optional - for push notifications)
  FCM_PROJECT_ID: getEnvOptional("FCM_PROJECT_ID"),
  FCM_CLIENT_EMAIL: getEnvOptional("FCM_CLIENT_EMAIL"),
  FCM_PRIVATE_KEY: getEnvOptional("FCM_PRIVATE_KEY"),
} as const;

export type Env = typeof env;
