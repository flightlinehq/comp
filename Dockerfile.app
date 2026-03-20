# =============================================================================
# STAGE 1: Dependencies - Install and cache workspace dependencies
# =============================================================================
FROM oven/bun:1.2.8 AS deps

WORKDIR /app

# Copy workspace configuration
COPY package.json bun.lock ./

# Copy package.json files for all workspace packages
COPY packages/kv/package.json ./packages/kv/
COPY packages/ui/package.json ./packages/ui/
COPY packages/email/package.json ./packages/email/
COPY packages/integration-platform/package.json ./packages/integration-platform/
COPY packages/integrations/package.json ./packages/integrations/
COPY packages/utils/package.json ./packages/utils/
COPY packages/tsconfig/package.json ./packages/tsconfig/
COPY packages/analytics/package.json ./packages/analytics/
COPY packages/auth/package.json ./packages/auth/
COPY packages/company/package.json ./packages/company/
COPY packages/db/package.json ./packages/db/
COPY packages/device-agent/package.json ./packages/device-agent/
COPY packages/docs/package.json ./packages/docs/

# Copy app package.json files
COPY apps/api/package.json ./apps/api/
COPY apps/app/package.json ./apps/app/
COPY apps/portal/package.json ./apps/portal/

# Install all dependencies
RUN PRISMA_SKIP_POSTINSTALL_GENERATE=true bun install --ignore-scripts

# =============================================================================
# STAGE 2: App Builder
# =============================================================================
FROM deps AS app-builder

WORKDIR /app

COPY packages ./packages
COPY apps/app ./apps/app
COPY --from=deps /app/node_modules ./node_modules

# Generate Prisma client and build workspace packages
RUN cd packages/db && node scripts/combine-schemas.js
RUN cp packages/db/dist/schema.prisma apps/app/prisma/schema.prisma
RUN bunx prisma generate --schema=packages/db/dist/schema.prisma
RUN cd packages/auth && bun run build
RUN cd packages/company && bun run build

ARG NEXT_PUBLIC_BETTER_AUTH_URL
ARG NEXT_PUBLIC_PORTAL_URL
ARG NEXT_PUBLIC_POSTHOG_KEY
ARG NEXT_PUBLIC_POSTHOG_HOST
ARG NEXT_PUBLIC_IS_DUB_ENABLED
ARG NEXT_PUBLIC_GTM_ID
ARG NEXT_PUBLIC_LINKEDIN_PARTNER_ID
ARG NEXT_PUBLIC_LINKEDIN_CONVERSION_ID
ARG NEXT_PUBLIC_GOOGLE_ADS_CONVERSION_LABEL
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_BETTER_AUTH_URL=$NEXT_PUBLIC_BETTER_AUTH_URL \
    NEXT_PUBLIC_PORTAL_URL=$NEXT_PUBLIC_PORTAL_URL \
    NEXT_PUBLIC_POSTHOG_KEY=$NEXT_PUBLIC_POSTHOG_KEY \
    NEXT_PUBLIC_POSTHOG_HOST=$NEXT_PUBLIC_POSTHOG_HOST \
    NEXT_PUBLIC_IS_DUB_ENABLED=$NEXT_PUBLIC_IS_DUB_ENABLED \
    NEXT_PUBLIC_GTM_ID=$NEXT_PUBLIC_GTM_ID \
    NEXT_PUBLIC_LINKEDIN_PARTNER_ID=$NEXT_PUBLIC_LINKEDIN_PARTNER_ID \
    NEXT_PUBLIC_LINKEDIN_CONVERSION_ID=$NEXT_PUBLIC_LINKEDIN_CONVERSION_ID \
    NEXT_PUBLIC_GOOGLE_ADS_CONVERSION_LABEL=$NEXT_PUBLIC_GOOGLE_ADS_CONVERSION_LABEL \
    NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_TELEMETRY_DISABLED=1 NODE_ENV=production \
    NEXT_OUTPUT_STANDALONE=true \
    NODE_OPTIONS=--max_old_space_size=6144

RUN cd apps/app && SKIP_ENV_VALIDATION=true bun run build:docker

# =============================================================================
# STAGE 3: App Production
# =============================================================================
FROM node:22-alpine

WORKDIR /app

COPY --from=app-builder /app/apps/app/.next/standalone ./
COPY --from=app-builder /app/apps/app/.next/static ./apps/app/.next/static
COPY --from=app-builder /app/apps/app/public ./apps/app/public

EXPOSE 3000
CMD ["node", "apps/app/server.js"]
