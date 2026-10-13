# Hosted MCP server (Streamable HTTP) for Cloud Run. The stdio entry (npx) is
# published to npm from the same source; this image only runs dist/http.js.
FROM --platform=linux/amd64 node:22-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM --platform=linux/amd64 node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/package.json ./
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
EXPOSE 8080
USER node
CMD ["node", "dist/http.js"]
