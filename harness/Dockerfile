# Real red-team harness image. Build context is harness/ (so the redteam
# submodule is available at ./redteam). Runs offline via tsx; scripted attacker
# needs no model. Reports are written to /app/redteam/reports (bind-mounted to /out).
# pi-coding-agent uses node:fs globSync (Node 22+), so pin 22.
FROM node:22-alpine
WORKDIR /app/redteam

# Install deps first for layer caching. Build tools in case a dep has native code.
COPY redteam/package.json redteam/package-lock.json* ./
RUN apk add --no-cache python3 make g++ \
 && (npm ci --no-audit --no-fund || npm install --no-audit --no-fund)

COPY redteam/ ./

# Entry: the scan CLI. The controller appends <repoUrl> [--flags] per invocation
# and passes TARGET_* / CANARY_FILE via `docker compose run -e`.
ENTRYPOINT ["npx", "tsx", "src/cli.ts"]
