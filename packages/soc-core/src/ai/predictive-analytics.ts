import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import pino from "pino";
import crypto from "crypto";

const log = pino({ name: "predictive-analytics", level: "info" });

const config = {
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  app: {
    port: parseInt(process.env.PORT || "8092"),
  },
};

interface AttackPrediction {
  id: string;
  type: string;
  likelihood: number;
  severity: number;
  timeframe: string;
  factors: PredictionFactor[];
  indicators: string[];
  mitigation: string[];
  createdAt: string;
}

interface PredictionFactor {
  name: string;
  weight: number;
  contribution: number;
}

interface AnomalyScore {
  id: string;
  entityType: string;
  entityValue: string;
  score: number;
  features: Record<string, number>;
  detectedAt: string;
}

interface TrendAnalysis {
  metric: string;
  current: number;
  previous: number;
  change: number;
  trend: "increasing" | "decreasing" | "stable";
  forecast: number[];
}

class PredictiveAnalyticsService {
  private redis: Redis;

  constructor() {
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  private calculateAnomalyScore(features: Record<string, number>): number {
    const weights: Record<string, number> = {
      failed_logins: 0.3,
      traffic_volume: 0.25,
      cpu_usage: 0.15,
      memory_usage: 0.15,
      network_connections: 0.15,
    };

    let score = 0;
    for (const [key, value] of Object.entries(features)) {
      const weight = weights[key] || 0.1;
      const normalized = Math.min(value / 100, 1);
      score += normalized * weight * 100;
    }

    return Math.round(score);
  }

  async detectAnomalies(
    entityType: string,
    entityValue: string,
    features: Record<string, number>,
  ): Promise<AnomalyScore> {
    const id = crypto.randomUUID();
    const score = this.calculateAnomalyScore(features);

    const result: AnomalyScore = {
      id,
      entityType,
      entityValue,
      score,
      features,
      detectedAt: new Date().toISOString(),
    };

    await this.redis.set(`anomaly:${id}`, JSON.stringify(result));
    await this.redis.expire(`anomaly:${id}`, 86400 * 7);

    return result;
  }

  async getAnomalies(limit = 50): Promise<AnomalyScore[]> {
    const keys = await this.redis.keys("anomaly:*");
    const anomalies: AnomalyScore[] = [];

    for (const key of keys.slice(0, limit)) {
      const data = await this.redis.get(key);
      if (data) anomalies.push(JSON.parse(data));
    }

    return anomalies.sort((a, b) => b.score - a.score);
  }

  async predictAttack(
    historicalData: Record<string, unknown>[],
  ): Promise<AttackPrediction[]> {
    const predictions: AttackPrediction[] = [];

    const attackTypes = [
      {
        type: "DDoS",
        likelihood: Math.random() * 40 + 20,
        severity: Math.random() * 5 + 5,
        factors: [
          { name: "Traffic spike", weight: 0.4, contribution: Math.random() },
          {
            name: "Connection count",
            weight: 0.3,
            contribution: Math.random(),
          },
          {
            name: "Geographic distribution",
            weight: 0.3,
            contribution: Math.random(),
          },
        ],
        indicators: ["High traffic volume", "Multiple source IPs"],
        mitigation: ["Rate limiting", "Traffic scrubbing", "IP blocking"],
      },
      {
        type: "Credential Attack",
        likelihood: Math.random() * 35 + 25,
        severity: Math.random() * 4 + 6,
        factors: [
          {
            name: "Failed login attempts",
            weight: 0.5,
            contribution: Math.random(),
          },
          {
            name: "Unusual login times",
            weight: 0.3,
            contribution: Math.random(),
          },
          { name: "New source IPs", weight: 0.2, contribution: Math.random() },
        ],
        indicators: ["Multiple failed logins", "Password spray patterns"],
        mitigation: ["MFA enforcement", "Account lockout", "IP reputation"],
      },
      {
        type: "Malware",
        likelihood: Math.random() * 30 + 15,
        severity: Math.random() * 6 + 4,
        factors: [
          {
            name: "Suspicious file downloads",
            weight: 0.4,
            contribution: Math.random(),
          },
          {
            name: "Unusual process activity",
            weight: 0.35,
            contribution: Math.random(),
          },
          {
            name: "Network beaconing",
            weight: 0.25,
            contribution: Math.random(),
          },
        ],
        indicators: ["New executables", "DNS anomalies"],
        mitigation: ["EDR deployment", "DNS filtering", "Sandboxing"],
      },
    ];

    for (const attack of attackTypes) {
      predictions.push({
        id: crypto.randomUUID(),
        type: attack.type,
        likelihood: Math.round(attack.likelihood),
        severity: Math.round(attack.severity),
        timeframe: "24-48 hours",
        factors: attack.factors,
        indicators: attack.indicators,
        mitigation: attack.mitigation,
        createdAt: new Date().toISOString(),
      });
    }

    for (const prediction of predictions) {
      await this.redis.set(
        `prediction:${prediction.id}`,
        JSON.stringify(prediction),
      );
      await this.redis.expire(`prediction:${prediction.id}`, 86400);
    }

    return predictions;
  }

  async analyzeTrends(metrics: string[]): Promise<TrendAnalysis[]> {
    const results: TrendAnalysis[] = [];

    for (const metric of metrics) {
      const current = Math.random() * 100;
      const previous = Math.random() * 100;
      const change = ((current - previous) / previous) * 100;

      const trend: TrendAnalysis = {
        metric,
        current: Math.round(current),
        previous: Math.round(previous),
        change: Math.round(change),
        trend:
          change > 5 ? "increasing" : change < -5 ? "decreasing" : "stable",
        forecast: Array.from({ length: 7 }, () =>
          Math.round(Math.random() * 100),
        ),
      };

      results.push(trend);
    }

    return results;
  }

  async getRiskScore(): Promise<{
    overall: number;
    categories: Record<string, number>;
    trend: "increasing" | "decreasing" | "stable";
  }> {
    const categories = [
      "network",
      "endpoint",
      "identity",
      "application",
      "data",
    ];

    const categoryScores: Record<string, number> = {};
    let total = 0;

    for (const cat of categories) {
      const score = Math.round(Math.random() * 50 + 20);
      categoryScores[cat] = score;
      total += score;
    }

    return {
      overall: Math.round(total / categories.length),
      categories: categoryScores,
      trend:
        Math.random() > 0.6
          ? "increasing"
          : Math.random() < 0.4
            ? "decreasing"
            : "stable",
    };
  }

  async getStats() {
    const [anomalyCount, predictionCount] = await Promise.all([
      this.redis.keys("anomaly:*").then((k) => k.length),
      this.redis.keys("prediction:*").then((k) => k.length),
    ]);

    return {
      anomalies: anomalyCount,
      predictions: predictionCount,
    };
  }
}

export async function buildApp(
  analytics: PredictiveAnalyticsService,
): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  app.get("/health", async () => ({ status: "ok" }));

  app.post("/api/v1/ai/predict/anomaly", async (request) => {
    const { entityType, entityValue, features } = request.body as {
      entityType: string;
      entityValue: string;
      features: Record<string, number>;
    };
    return analytics.detectAnomalies(entityType, entityValue, features);
  });

  app.get("/api/v1/ai/predict/anomalies", async (request) => {
    const limit = Number(request.query["limit"] || 50);
    return analytics.getAnomalies(limit);
  });

  app.post("/api/v1/ai/predict/attack", async (request) => {
    const { historicalData } = request.body as {
      historicalData: Record<string, unknown>[];
    };
    return analytics.predictAttack(historicalData || []);
  });

  app.post("/api/v1/ai/predict/trends", async (request) => {
    const { metrics } = request.body as { metrics: string[] };
    return analytics.analyzeTrends(metrics || ["alerts", "incidents", "logs"]);
  });

  app.get("/api/v1/ai/predict/risk", async () => {
    return analytics.getRiskScore();
  });

  app.get("/api/v1/ai/predict/stats", async () => {
    return analytics.getStats();
  });

  return app;
}

async function main() {
  const analytics = new PredictiveAnalyticsService();

  const app = await buildApp(analytics);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`Predictive Analytics API listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
