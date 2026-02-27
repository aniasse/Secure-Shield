FROM oven/bun:1-alpine AS base

WORKDIR /app

COPY package.json ./
RUN bun install

COPY src/ ./src/

FROM base AS siem
EXPOSE 8080
CMD ["bun", "run", "src/siem/index.ts"]

FROM base AS threat-intel
EXPOSE 8081
CMD ["bun", "run", "src/threat-intel/index.ts"]

FROM base AS soar
EXPOSE 8082
CMD ["bun", "run", "src/soar/index.ts"]

FROM base AS ml-detector
EXPOSE 8083
CMD ["bun", "run", "src/ml/detector.ts"]

FROM base AS sandbox
EXPOSE 8084
CMD ["bun", "run", "src/sandbox/index.ts"]

FROM base AS fraud-detector
EXPOSE 8085
CMD ["bun", "run", "src/fraud/index.ts"]

FROM base AS academy
EXPOSE 8086
CMD ["bun", "run", "src/academy/index.ts"]

FROM base AS llm-analyzer
EXPOSE 8090
CMD ["bun", "run", "src/ai/llm-analyzer.ts"]

FROM base AS threat-hunter
EXPOSE 8091
CMD ["bun", "run", "src/ai/threat-hunter.ts"]

FROM base AS predictive-analytics
EXPOSE 8092
CMD ["bun", "run", "src/ai/predictive-analytics.ts"]

FROM base AS reports
EXPOSE 8087
CMD ["bun", "run", "src/reports/index.ts"]

FROM base AS websocket
EXPOSE 8088
CMD ["bun", "run", "src/websocket/index.ts"]
