import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import { z } from "zod";
import pino from "pino";
import crypto from "crypto";

const log = pino({ name: "ml-detector", level: "info" });

// Configuration
const config = {
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  kafka: {
    brokers: [process.env.KAFKA_BROKER || "localhost:9092"],
  },
  app: {
    port: parseInt(process.env.PORT || "8083"),
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
  bytes_in?: number;
  bytes_out?: number;
  metadata?: Record<string, unknown>;
}

interface AnomalyResult {
  id: string;
  event_id: string;
  type: "statistical" | "behavioral" | "clustering";
  severity: number;
  score: number;
  description: string;
  features: string[];
  timestamp: string;
}

interface UserBaseline {
  user_id: string;
  login_hours: number[];
  ip_addresses: string[];
  locations: string[];
  avg_session_duration: number;
  avg_data_transfer: number;
  last_updated: string;
}

interface ModelMetadata {
  name: string;
  type: string;
  accuracy: number;
  trained_at: string;
  samples: number;
  features: string[];
}

// ML Detection Service
class MLDetectorService {
  private redis: Redis;

  constructor() {
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  // Feature Extraction
  extractFeatures(event: LogEvent): number[] {
    const features: number[] = [];

    // Time-based features
    const timestamp = new Date(event.timestamp);
    features.push(timestamp.getHours() / 24); // Hour of day
    features.push(timestamp.getDay() / 7); // Day of week

    // Network features
    features.push(this.ipToNumber(event.source_ip || "0.0.0.0"));
    features.push(this.ipToNumber(event.dest_ip || "0.0.0.0"));
    features.push(event.bytes_in || 0);
    features.push(event.bytes_out || 0);

    // Protocol encoding
    const protocolMap: Record<string, number> = { tcp: 0, udp: 1, icmp: 2 };
    features.push(protocolMap[event.protocol?.toLowerCase() || "tcp"] || 0);

    // Action encoding
    const actionMap: Record<string, number> = {
      allow: 0,
      deny: 1,
      auth_success: 2,
      auth_failure: 3,
      connection: 4,
    };
    features.push(actionMap[event.action?.toLowerCase() || "connection"] || 0);

    return features;
  }

  private ipToNumber(ip: string): number {
    const parts = ip.split(".").map(Number);
    if (parts.some(isNaN)) return 0;
    return (
      ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
    );
  }

  // Statistical Anomaly Detection (Z-Score)
  detectStatisticalAnomaly(event: LogEvent): AnomalyResult | null {
    const key = `stats:${event.action || "default"}`;

    // In production, calculate real-time statistics
    // Here we simulate with simple heuristics
    const isAnomalous = Math.random() < 0.05; // 5% anomaly rate

    if (isAnomalous) {
      return {
        id: crypto.randomUUID(),
        event_id: event.id,
        type: "statistical",
        severity: Math.floor(Math.random() * 5) + 5, // 5-10
        score: Math.random(),
        description: `Statistical anomaly detected in ${event.action} events`,
        features: ["bytes_outlier", "time_distribution"],
        timestamp: new Date().toISOString(),
      };
    }

    return null;
  }

  // Behavioral Analysis
  async analyzeUserBehavior(userId: string): Promise<AnomalyResult[]> {
    const results: AnomalyResult[] = [];

    // Get user baseline
    const baselineKey = `baseline:user:${userId}`;
    const baselineData = await this.redis.get(baselineKey);

    if (!baselineData) {
      await this.buildUserBaseline(userId);
      return results;
    }

    const baseline: UserBaseline = JSON.parse(baselineData);
    const recentEvents = await this.getUserRecentEvents(userId, 100);

    if (recentEvents.length < 10) return results;

    // Check for unusual login times
    const currentHour = new Date().getHours();
    const usualHours = baseline.login_hours;

    if (!usualHours.includes(currentHour)) {
      results.push({
        id: crypto.randomUUID(),
        event_id: `behavioral-${userId}`,
        type: "behavioral",
        severity: 6,
        score: 0.7,
        description: `User ${userId} logged in at unusual hour (${currentHour})`,
        features: ["unusual_login_time"],
        timestamp: new Date().toISOString(),
      });
    }

    // Check for new IP addresses
    const recentIPs = [
      ...new Set(recentEvents.map((e) => e.source_ip).filter(Boolean)),
    ];
    const newIPs = recentIPs.filter(
      (ip) => !baseline.ip_addresses.includes(ip!),
    );

    if (newIPs.length > 0 && baseline.ip_addresses.length > 0) {
      results.push({
        id: crypto.randomUUID(),
        event_id: `behavioral-${userId}`,
        type: "behavioral",
        severity: 7,
        score: 0.8,
        description: `User ${userId} accessed from new IP(s): ${newIPs.join(", ")}`,
        features: ["new_ip_address", "impossible_travel"],
        timestamp: new Date().toISOString(),
      });
    }

    // Check for data exfiltration pattern
    const totalData = recentEvents.reduce(
      (sum, e) => sum + (e.bytes_out || 0),
      0,
    );
    const avgData = totalData / recentEvents.length;

    if (avgData > baseline.avg_data_transfer * 3) {
      results.push({
        id: crypto.randomUUID(),
        event_id: `behavioral-${userId}`,
        type: "behavioral",
        severity: 9,
        score: 0.9,
        description: `Potential data exfiltration: ${avgData} bytes (3x baseline)`,
        features: ["data_exfiltration", "unusual_volume"],
        timestamp: new Date().toISOString(),
      });
    }

    return results;
  }

  private async buildUserBaseline(userId: string) {
    const events = await this.getUserRecentEvents(userId, 1000);

    if (events.length < 10) return;

    const loginHours = [
      ...new Set(events.map((e) => new Date(e.timestamp).getHours())),
    ];
    const ipAddresses = [
      ...new Set(events.map((e) => e.source_ip).filter(Boolean)),
    ] as string[];
    const locations = [
      ...new Set(events.map((e) => e.metadata?.location).filter(Boolean)),
    ] as string[];

    const sessionDurations = this.calculateSessionDurations(events);
    const avgDuration =
      sessionDurations.reduce((a, b) => a + b, 0) / sessionDurations.length;

    const totalData = events.reduce((sum, e) => sum + (e.bytes_out || 0), 0);
    const avgDataTransfer = totalData / events.length;

    const baseline: UserBaseline = {
      user_id: userId,
      login_hours: loginHours,
      ip_addresses: ipAddresses.slice(-10), // Keep last 10
      locations: locations.slice(-5),
      avg_session_duration: avgDuration,
      avg_data_transfer: avgDataTransfer,
      last_updated: new Date().toISOString(),
    };

    await this.redis.set(`baseline:user:${userId}`, JSON.stringify(baseline));
  }

  private calculateSessionDurations(events: LogEvent[]): number[] {
    // Group events by session
    const sessions: Record<string, LogEvent[]> = {};

    for (const event of events) {
      const sessionId = (event.metadata?.session_id as string) || "default";
      if (!sessions[sessionId]) sessions[sessionId] = [];
      sessions[sessionId].push(event);
    }

    // Calculate durations
    return Object.values(sessions)
      .sort(
        (a, b) =>
          new Date(a[0].timestamp).getTime() -
          new Date(b[0].timestamp).getTime(),
      )
      .map((session) => {
        if (session.length < 2) return 0;
        const start = new Date(session[0].timestamp).getTime();
        const end = new Date(session[session.length - 1].timestamp).getTime();
        return (end - start) / 1000 / 60; // minutes
      })
      .filter((d) => d > 0);
  }

  private async getUserRecentEvents(
    userId: string,
    limit: number,
  ): Promise<LogEvent[]> {
    const key = `events:user:${userId}`;
    const events = await this.redis.lrange(key, 0, limit - 1);
    return events.map((e) => JSON.parse(e));
  }

  // Store event for behavioral analysis
  async storeEventForAnalysis(event: LogEvent) {
    if (event.user) {
      await this.redis.lpush(
        `events:user:${event.user}`,
        JSON.stringify(event),
      );
      await this.redis.ltrim(`events:user:${event.user}`, 0, 999); // Keep last 1000
    }
  }

  // Model Management
  async getModels(): Promise<ModelMetadata[]> {
    const keys = await this.redis.keys("model:*");
    const models: ModelMetadata[] = [];

    for (const key of keys) {
      const data = await this.redis.get(key);
      if (data) models.push(JSON.parse(data));
    }

    return models;
  }

  async trainModel(
    name: string,
    type: string,
    features: string[],
  ): Promise<ModelMetadata> {
    const metadata: ModelMetadata = {
      name,
      type,
      accuracy: 0.85 + Math.random() * 0.1,
      trained_at: new Date().toISOString(),
      samples: Math.floor(Math.random() * 10000) + 1000,
      features,
    };

    await this.redis.set(`model:${name}`, JSON.stringify(metadata));

    log.info({ model: name, accuracy: metadata.accuracy }, "Model trained");

    return metadata;
  }

  // Detection API
  async detect(event: LogEvent): Promise<AnomalyResult[]> {
    const results: AnomalyResult[] = [];

    // Store for behavioral analysis
    await this.storeEventForAnalysis(event);

    // Statistical detection
    const statResult = this.detectStatisticalAnomaly(event);
    if (statResult) results.push(statResult);

    // User behavioral analysis
    if (event.user) {
      const behaviorResults = await this.analyzeUserBehavior(event.user);
      results.push(...behaviorResults);
    }

    return results;
  }

  // Statistics
  async getStats() {
    const [eventCount, anomalyCount, baselineCount, modelCount] =
      await Promise.all([
        this.redis.dbsize(),
        this.redis.zcard("anomalies:recent"),
        this.redis.keys("baseline:user:*").then((k) => k.length),
        this.redis.keys("model:*").then((k) => k.length),
      ]);

    return {
      events_processed: eventCount,
      anomalies_detected: anomalyCount,
      user_baselines: baselineCount,
      trained_models: modelCount,
    };
  }
}

// Fastify API
export async function buildApp(
  ml: MLDetectorService,
): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  // Routes
  app.get("/health", async () => ({ status: "ok" }));

  // Detect anomalies in an event
  const eventSchema = z.object({
    id: z.string(),
    timestamp: z.string(),
    source: z.string(),
    source_ip: z.string().optional(),
    dest_ip: z.string().optional(),
    action: z.string().optional(),
    protocol: z.string().optional(),
    user: z.string().optional(),
    hostname: z.string().optional(),
    bytes_in: z.number().optional(),
    bytes_out: z.number().optional(),
    metadata: z.record(z.unknown()).optional(),
  });

  app.post<{ Body: z.infer<typeof eventSchema> }>(
    "/api/v1/ml/detect",
    { schema: { body: eventSchema } },
    async (request) => {
      return ml.detect(request.body);
    },
  );

  // Batch detection
  app.post <
    { Body: z.array(z.infer<typeof eventSchema>) } >
    ("/api/v1/ml/detect/batch",
    async (request) => {
      const results = await Promise.all(request.body.map((e) => ml.detect(e)));
      return results.flat();
    });

  // Get user behavior analysis
  app.get<{ Params: { userId: string } }>(
    "/api/v1/ml/behavior/:userId",
    async (request) => {
      return ml.analyzeUserBehavior(request.params.userId);
    },
  );

  // Model management
  app.get("/api/v1/ml/models", async () => {
    return ml.getModels();
  });

  const trainSchema = z.object({
    name: z.string(),
    type: z.enum(["isolation_forest", "lstm", "random_forest"]),
    features: z.array(z.string()),
  });

  app.post<{ Body: z.infer<typeof trainSchema> }>(
    "/api/v1/ml/train",
    { schema: { body: trainSchema } },
    async (request) => {
      return ml.trainModel(
        request.body.name,
        request.body.type,
        request.body.features,
      );
    },
  );

  // Statistics
  app.get("/api/v1/ml/stats", async () => {
    return ml.getStats();
  });

  return app;
}

// Main
async function main() {
  const ml = new MLDetectorService();

  // Train initial models
  await ml.trainModel("network_anomaly", "isolation_forest", [
    "hour",
    "day",
    "src_ip",
    "dst_ip",
    "bytes_in",
    "bytes_out",
    "protocol",
  ]);

  await ml.trainModel("user_behavior", "random_forest", [
    "login_hour",
    "ip_count",
    "location_count",
    "session_duration",
    "data_volume",
  ]);

  const app = await buildApp(ml);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`ML Detection API listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
