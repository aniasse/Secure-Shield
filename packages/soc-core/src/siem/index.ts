import { Kafka, logLevel, EachMessagePayload } from "kafkajs";
import { Client } from "@elastic/elasticsearch";
import Redis from "ioredis";
import { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import fastifyJwt from "@fastify/jwt";
import fastifyCors from "@fastify/cors";
import { z } from "zod";
import pino from "pino";

const log = pino({ name: "soc-core", level: "info" });

// Configuration
const config = {
  kafka: {
    brokers: [process.env.KAFKA_BROKER || "localhost:9092"],
    clientId: "soc-core",
    groupId: "soc-siem-group",
  },
  elasticsearch: {
    node: process.env.ES_NODE || "http://localhost:9200",
  },
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  app: {
    port: parseInt(process.env.PORT || "8080"),
    jwtSecret: process.env.JWT_SECRET || "dev-secret-change-in-prod",
  },
};

// Types
interface LogEvent {
  id: string;
  timestamp: string;
  source: string;
  source_ip?: string;
  dest_ip?: string;
  action?: string;
  protocol?: string;
  user?: string;
  hostname?: string;
  raw: string;
  metadata?: Record<string, unknown>;
}

interface Alert {
  id: string;
  timestamp: string;
  severity: number;
  confidence: number;
  title: string;
  description: string;
  mitre_technique?: string;
  iocs?: string[];
  affected_assets?: string[];
  status: "new" | "in_progress" | "resolved";
  assigned_to?: string;
}

interface ThreatIntel {
  indicator: string;
  type: "ip" | "domain" | "hash" | "url";
  reputation: "malicious" | "suspicious" | "clean" | "unknown";
  confidence: number;
  sources: string[];
  tags: string[];
  first_seen?: string;
  last_seen?: string;
}

// Services
class SIEMService {
  private kafka: Kafka;
  private es: Client;
  private redis: Redis;

  constructor() {
    this.kafka = new Kafka({
      clientId: config.kafka.clientId,
      brokers: config.kafka.brokers,
      logLevel: logLevel.WARN,
    });

    this.es = new Client({
      node: config.elasticsearch.node,
    });

    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  async start() {
    await this.startLogConsumer();
    log.info("SIEM service started");
  }

  private async startLogConsumer() {
    const consumer = this.kafka.consumer({ groupId: config.kafka.groupId });

    await consumer.connect();
    await consumer.subscribe({ topic: "logs.raw", fromBeginning: false });

    await consumer.run({
      eachMessage: async (payload: EachMessagePayload) => {
        await this.processLog(payload);
      },
    });
  }

  private async processLog(payload: EachMessagePayload) {
    try {
      const event: LogEvent = JSON.parse(
        payload.message.value?.toString() || "{}",
      );

      // Store in Elasticsearch
      await this.storeEvent(event);

      // Run detection
      const alerts = await this.detectThreats(event);

      // Publish alerts
      for (const alert of alerts) {
        await this.publishAlert(alert);
      }
    } catch (error) {
      log.error({ error }, "Failed to process log");
    }
  }

  private async storeEvent(event: LogEvent) {
    const indexName = `logs-${event.source}-${event.timestamp.split("T")[0]}`;

    await this.es.index({
      index: indexName,
      id: event.id,
      document: event,
    });
  }

  private async detectThreats(event: LogEvent): Promise<Alert[]> {
    const alerts: Alert[] = [];

    // Rule 1: Multiple failed logins
    if (event.action === "auth_failure") {
      const key = `auth_failures:${event.source_ip}`;
      const count = await this.redis.incr(key);

      if (count === 1) {
        await this.redis.expire(key, 300); // 5 minutes
      }

      if (count >= 5) {
        alerts.push({
          id: `alert-${Date.now()}`,
          timestamp: new Date().toISOString(),
          severity: 7,
          confidence: 90,
          title: "Brute Force Attack Detected",
          description: `Multiple authentication failures from ${event.source_ip}`,
          mitre_technique: "T1110",
          iocs: [event.source_ip || ""],
          status: "new",
        });
      }
    }

    // Rule 2: Suspicious outbound connections
    if (event.action === "outbound_connection") {
      const suspiciousPorts = ["4444", "5555", "6666", "31337"];
      if (
        event.metadata?.dest_port &&
        suspiciousPorts.includes(String(event.metadata.dest_port))
      ) {
        alerts.push({
          id: `alert-${Date.now()}`,
          timestamp: new Date().toISOString(),
          severity: 9,
          confidence: 85,
          title: "Suspicious Outbound Connection",
          description: `Connection to suspicious port ${event.metadata?.dest_port}`,
          mitre_technique: "T1071",
          iocs: [event.dest_ip || ""],
          status: "new",
        });
      }
    }

    // Rule 3: Privilege escalation attempt
    if (event.action === "sudo" || event.action === "root_access") {
      alerts.push({
        id: `alert-${Date.now()}`,
        timestamp: new Date().toISOString(),
        severity: 8,
        confidence: 75,
        title: "Privilege Escalation Attempt",
        description: `User ${event.user} attempted privileged access on ${event.hostname}`,
        mitre_technique: "T1068",
        affected_assets: [event.hostname || ""],
        status: "new",
      });
    }

    // Check against threat intelligence
    if (event.source_ip) {
      const ti = await this.checkThreatIntel(event.source_ip);
      if (ti && ti.reputation === "malicious") {
        alerts.push({
          id: `alert-${Date.now()}`,
          timestamp: new Date().toISOString(),
          severity: 10,
          confidence: ti.confidence,
          title: "Known Malicious IP",
          description: `Connection from known malicious IP ${event.source_ip}`,
          mitre_technique: "T1072",
          iocs: [event.source_ip],
          status: "new",
        });
      }
    }

    return alerts;
  }

  private async checkThreatIntel(ip: string): Promise<ThreatIntel | null> {
    const cached = await this.redis.get(`ti:ip:${ip}`);
    if (cached) {
      return JSON.parse(cached);
    }

    // In production, query MISP, VirusTotal, etc.
    return null;
  }

  private async publishAlert(alert: Alert) {
    const producer = this.kafka.producer();
    await producer.connect();
    await producer.send({
      topic: "alerts",
      messages: [{ key: alert.id, value: JSON.stringify(alert) }],
    });
    await producer.disconnect();
  }

  // API Methods
  async searchLogs(query: string, from?: string, to?: string, size = 100) {
    const response = await this.es.search({
      index: "logs-*",
      body: {
        query: {
          bool: {
            must: [
              { query_string: { query } },
              ...(from && to
                ? [{ range: { timestamp: { gte: from, lte: to } } }]
                : []),
            ],
          },
        },
        sort: [{ timestamp: { order: "desc" } }],
        size,
      },
    });

    return response.hits.hits.map((hit: any) => hit._source);
  }

  async getAlerts(filters?: {
    severity?: number;
    status?: string;
    from?: string;
    to?: string;
  }) {
    const must: any[] = [];

    if (filters?.severity) {
      must.push({ term: { severity: filters.severity } });
    }
    if (filters?.status) {
      must.push({ term: { status: filters.status } });
    }
    if (filters?.from && filters?.to) {
      must.push({
        range: { timestamp: { gte: filters.from, lte: filters.to } },
      });
    }

    const response = await this.es.search({
      index: "alerts-*",
      body: {
        query: { bool: { must: must.length > 0 ? must : [{ match_all: {} }] } },
        sort: [{ timestamp: { order: "desc" } }],
        size: 100,
      },
    });

    return response.hits.hits.map((hit: any) => hit._source);
  }

  async updateAlertStatus(
    alertId: string,
    status: string,
    assignedTo?: string,
  ) {
    await this.es.update({
      index: "alerts-*",
      id: alertId,
      doc: { status, assigned_to: assignedTo },
    });
  }
}

// Fastify API
async function buildApp(siem: SIEMService) {
  const app: FastifyInstance = await import("fastify").then((f) => f.default());

  await app.register(fastifyCors);
  await app.register(fastifyJwt, {
    secret: config.app.jwtSecret,
  });

  // Auth decorator
  app.decorate(
    "authenticate",
    async (request: FastifyRequest, reply: FastifyReply) => {
      try {
        await request.jwtVerify();
      } catch (err) {
        reply.send(err);
      }
    },
  );

  // Routes
  app.get("/health", async () => ({ status: "ok" }));

  // Logs
  const logsQuerySchema = z.object({
    q: z.string().optional(),
    from: z.string().optional(),
    to: z.string().optional(),
    size: z.number().optional(),
  });

  app.get(
    "/api/v1/logs",
    {
      schema: { querystring: logsQuerySchema },
    },
    async (
      request: FastifyRequest<{ Querystring: z.infer<typeof logsQuerySchema> }>,
      reply,
    ) => {
      const { q, from, to, size } = request.query;
      const results = await siem.searchLogs(q || "*", from, to, size);
      return results;
    },
  );

  // Alerts
  const alertsQuerySchema = z.object({
    severity: z.number().optional(),
    status: z.string().optional(),
    from: z.string().optional(),
    to: z.string().optional(),
  });

  app.get(
    "/api/v1/alerts",
    {
      schema: { querystring: alertsQuerySchema },
    },
    async (
      request: FastifyRequest<{
        Querystring: z.infer<typeof alertsQuerySchema>;
      }>,
      reply,
    ) => {
      const results = await siem.getAlerts(request.query);
      return results;
    },
  );

  const alertUpdateSchema = z.object({
    status: z.enum(["new", "in_progress", "resolved"]),
    assigned_to: z.string().optional(),
  });

  app.patch(
    "/api/v1/alerts/:id",
    {
      schema: { body: alertUpdateSchema },
    },
    async (
      request: FastifyRequest<{
        Params: { id: string };
        Body: z.infer<typeof alertUpdateSchema>;
      }>,
      reply,
    ) => {
      const { id } = request.params;
      const { status, assigned_to } = request.body;
      await siem.updateAlertStatus(id, status, assigned_to);
      return { success: true };
    },
  );

  // Dashboard stats
  app.get("/api/v1/stats", async () => {
    const es = new Client({ node: config.elasticsearch.node });

    const [alerts, logs] = await Promise.all([
      es.search({
        index: "alerts-*",
        body: { size: 0, query: { match_all: {} } },
      }),
      es.search({
        index: "logs-*",
        body: { size: 0, query: { match_all: {} } },
      }),
    ]);

    return {
      total_alerts: alerts.hits.total,
      total_logs: logs.hits.total,
      severity_breakdown: {
        critical: await siem.getAlerts({ severity: 10 }).then((r) => r.length),
        high: await siem.getAlerts({ severity: 8 }).then((r) => r.length),
        medium: await siem.getAlerts({ severity: 5 }).then((r) => r.length),
        low: await siem.getAlerts({ severity: 3 }).then((r) => r.length),
      },
    };
  });

  return app;
}

// Main
async function main() {
  const siem = new SIEMService();

  // Start Kafka consumer in background
  siem.start().catch((err) => log.error({ err }, "SIEM start failed"));

  // Start API server
  const app = await buildApp(siem);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`API server listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
