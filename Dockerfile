# ===================================
# Food Queue Reservation API
# Production Dockerfile (FIXED)
# ===================================

FROM oven/bun:1.3.1 AS base
WORKDIR /app

# ---------------------------
# Install dependencies
# ---------------------------
FROM base AS deps
COPY package.json bun.lockb* ./
RUN bun install --frozen-lockfile

# ---------------------------
# Prisma generate
# ---------------------------
FROM base AS prisma
COPY --from=deps /app/node_modules ./node_modules
COPY prisma ./prisma
# Prisma generate ไม่ต้องใช้ DATABASE_URL
RUN bunx prisma generate

# ---------------------------
# Build
# ---------------------------
FROM base AS builder
COPY --from=deps /app/node_modules ./node_modules
COPY --from=prisma /app/node_modules/.prisma ./node_modules/.prisma
COPY . .

# ---------------------------
# Production
# ---------------------------
FROM base AS runner
ENV NODE_ENV=production

# Prisma ต้องรู้ provider ตอน runtime
ENV PRISMA_CLIENT_ENGINE_TYPE=binary

# ⚠️ DATABASE_URL ต้องส่งตอน docker run
# ENV DATABASE_URL=

# non-root user
RUN addgroup --system --gid 1001 nodejs \
 && adduser --system --uid 1001 elysia
USER elysia

# copy files
COPY --from=builder --chown=elysia:nodejs /app/node_modules ./node_modules
COPY --from=builder --chown=elysia:nodejs /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder --chown=elysia:nodejs /app/src ./src
COPY --from=builder --chown=elysia:nodejs /app/prisma ./prisma
COPY --from=builder --chown=elysia:nodejs /app/package.json ./

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["bun", "run", "src/index.ts"]
