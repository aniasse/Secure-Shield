import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import { z } from "zod";
import pino from "pino";
import crypto from "crypto";

const log = pino({ name: "fraud-detector", level: "info" });

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
    port: parseInt(process.env.PORT || "8085"),
  },
};

// Types
interface Transaction {
  id: string;
  timestamp: string;
  user_id: string;
  amount: number;
  currency: string;
  type: "payment" | "transfer" | "withdrawal" | "refund";
  status: "pending" | "completed" | "failed" | "flagged";
  payment_method?: string;
  merchant_id?: string;
  merchant_category?: string;
  location?: string;
  ip_address?: string;
  device_fingerprint?: string;
  metadata?: Record<string, unknown>;
}

interface FraudRule {
  id: string;
  name: string;
  description: string;
  type:
    | "velocity"
    | "amount"
    | "geographic"
    | "device"
    | "behavioral"
    | "pattern";
  parameters: Record<string, unknown>;
  severity: number; // 1-10
  enabled: boolean;
}

interface FraudAlert {
  id: string;
  transaction_id: string;
  rule_id: string;
  rule_name: string;
  severity: number;
  score: number;
  description: string;
  recommendations: string[];
  status: "new" | "investigating" | "confirmed" | "false_positive" | "resolved";
  created_at: string;
  resolved_at?: string;
  resolved_by?: string;
  notes?: string;
}

interface RiskScore {
  user_id: string;
  score: number; // 0-100
  factors: RiskFactor[];
  last_updated: string;
}

interface RiskFactor {
  type: string;
  description: string;
  impact: number; // contribution to score
  triggered_at: string;
}

// Fraud Detection Service
class FraudDetectionService {
  private redis: Redis;
  private rules: Map<string, FraudRule>;

  constructor() {
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
    this.rules = new Map();
    this.initializeRules();
  }

  private initializeRules() {
    const defaultRules: FraudRule[] = [
      {
        id: "velocity_1h",
        name: "High Velocity Transactions",
        description: "More than 5 transactions in 1 hour",
        type: "velocity",
        parameters: { window_seconds: 3600, max_count: 5 },
        severity: 6,
        enabled: true,
      },
      {
        id: "velocity_24h",
        name: "Very High Velocity",
        description: "More than 20 transactions in 24 hours",
        type: "velocity",
        parameters: { window_seconds: 86400, max_count: 20 },
        severity: 8,
        enabled: true,
      },
      {
        id: "amount_single",
        name: "High Value Transaction",
        description: "Single transaction exceeds threshold",
        type: "amount",
        parameters: { threshold: 10000 },
        severity: 7,
        enabled: true,
      },
      {
        id: "amount_daily",
        name: "High Daily Total",
        description: "Daily transaction total exceeds limit",
        type: "amount",
        parameters: { threshold: 25000, window_seconds: 86400 },
        severity: 8,
        enabled: true,
      },
      {
        id: "geo_impossible",
        name: "Impossible Travel",
        description:
          "Transactions from geographically distant locations in short time",
        type: "geographic",
        parameters: { max_distance_km: 500, max_time_minutes: 60 },
        severity: 9,
        enabled: true,
      },
      {
        id: "new_device",
        name: "New Device",
        description: "First transaction from new device",
        type: "device",
        parameters: {},
        severity: 4,
        enabled: true,
      },
      {
        id: "high_risk_merchant",
        name: "High Risk Merchant",
        description: "Transaction with high-risk merchant category",
        type: "pattern",
        parameters: { categories: ["gambling", "crypto", "adult"] },
        severity: 6,
        enabled: true,
      },
      {
        id: "off_hours",
        name: "Off-Hours Transaction",
        description: "Transaction outside normal business hours (local time)",
        type: "behavioral",
        parameters: { allowed_hours: [8, 22] },
        severity: 3,
        enabled: true,
      },
    ];

    for (const rule of defaultRules) {
      this.rules.set(rule.id, rule);
    }
  }

  // Evaluate single transaction
  async evaluateTransaction(
    transaction: Transaction,
  ): Promise<{ alerts: FraudAlert[]; riskScore: number }> {
    const alerts: FraudAlert[] = [];
    let totalRiskScore = 0;

    // Get user history
    const userHistory = await this.getUserTransactionHistory(
      transaction.user_id,
    );

    // Check each enabled rule
    for (const [_, rule] of this.rules) {
      if (!rule.enabled) continue;

      const result = await this.checkRule(rule, transaction, userHistory);

      if (result.triggered) {
        const alert: FraudAlert = {
          id: crypto.randomUUID(),
          transaction_id: transaction.id,
          rule_id: rule.id,
          rule_name: rule.name,
          severity: rule.severity,
          score: result.score,
          description: result.description,
          recommendations: result.recommendations,
          status: "new",
          created_at: new Date().toISOString(),
        };

        alerts.push(alert);
        totalRiskScore += result.score;
      }
    }

    // Store transaction for future analysis
    await this.storeTransaction(transaction);

    // Update user risk score
    const riskScore = Math.min(totalRiskScore, 100);
    await this.updateUserRiskScore(transaction.user_id, riskScore);

    return { alerts, riskScore };
  }

  private async checkRule(
    rule: FraudRule,
    transaction: Transaction,
    history: Transaction[],
  ): Promise<{
    triggered: boolean;
    score: number;
    description: string;
    recommendations: string[];
  }> {
    switch (rule.type) {
      case "velocity": {
        const params = rule.parameters as {
          window_seconds: number;
          max_count: number;
        };
        const cutoff = Date.now() - params.window_seconds * 1000;
        const recentCount = history.filter(
          (t) => new Date(t.timestamp).getTime() > cutoff,
        ).length;

        if (recentCount >= params.max_count) {
          return {
            triggered: true,
            score: rule.severity * 10,
            description: `${recentCount} transactions in ${params.window_seconds / 3600}h (max: ${params.max_count})`,
            recommendations: [
              "Verify user identity via phone",
              "Request additional authentication",
              "Review recent account activity",
            ],
          };
        }
        break;
      }

      case "amount": {
        const params = rule.parameters as { threshold: number };

        if (transaction.amount >= params.threshold) {
          return {
            triggered: true,
            score: rule.severity * 10,
            description: `Transaction amount ${transaction.amount} exceeds threshold ${params.threshold}`,
            recommendations: [
              "Require manual approval",
              "Verify with card issuer",
              "Contact customer directly",
            ],
          };
        }
        break;
      }

      case "geographic": {
        const params = rule.parameters as {
          max_distance_km: number;
          max_time_minutes: number;
        };

        if (history.length > 0) {
          const lastTx = history.sort(
            (a, b) =>
              new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime(),
          )[0];

          // Simplified - in production use proper geolocation
          if (
            lastTx.location &&
            transaction.location &&
            lastTx.location !== transaction.location
          ) {
            // Would calculate actual distance
            return {
              triggered: true,
              score: rule.severity * 10,
              description: `Location change: ${lastTx.location} → ${transaction.location}`,
              recommendations: [
                "Verify transaction with customer",
                "Request additional verification",
              ],
            };
          }
        }
        break;
      }

      case "device": {
        if (history.length > 0) {
          const knownDevices = [
            ...new Set(
              history.map((t) => t.device_fingerprint).filter(Boolean),
            ),
          ];

          if (
            transaction.device_fingerprint &&
            !knownDevices.includes(transaction.device_fingerprint)
          ) {
            return {
              triggered: true,
              score: rule.severity * 10,
              description: "First transaction from this device",
              recommendations: [
                "Send device verification email",
                "Require 2FA",
              ],
            };
          }
        }
        break;
      }

      case "pattern": {
        const params = rule.parameters as { categories: string[] };

        if (
          transaction.merchant_category &&
          params.categories.includes(
            transaction.merchant_category.toLowerCase(),
          )
        ) {
          return {
            triggered: true,
            score: rule.severity * 10,
            description: `High-risk merchant category: ${transaction.merchant_category}`,
            recommendations: [
              "Enhanced due diligence",
              "Review merchant reputation",
            ],
          };
        }
        break;
      }

      case "behavioral": {
        const params = rule.parameters as { allowed_hours: number[] };
        const hour = new Date(transaction.timestamp).getHours();

        if (!params.allowed_hours.includes(hour)) {
          return {
            triggered: true,
            score: rule.severity * 10,
            description: `Transaction at unusual hour: ${hour}:00`,
            recommendations: ["Send verification notification"],
          };
        }
        break;
      }
    }

    return { triggered: false, score: 0, description: "", recommendations: [] };
  }

  private async getUserTransactionHistory(
    userId: string,
  ): Promise<Transaction[]> {
    const key = `transactions:user:${userId}`;
    const data = await this.redis.lrange(key, 0, 99);
    return data.map((d) => JSON.parse(d));
  }

  private async storeTransaction(transaction: Transaction) {
    const key = `transactions:user:${transaction.user_id}`;
    await this.redis.lpush(key, JSON.stringify(transaction));
    await this.redis.ltrim(key, 0, 99); // Keep last 100
  }

  async updateUserRiskScore(userId: string, score: number) {
    const key = `risk:user:${userId}`;
    const factors: RiskFactor[] = [];

    // Determine contributing factors
    if (score > 70) {
      factors.push({
        type: "high_risk_activity",
        description: "Multiple high-risk transactions detected",
        impact: score,
        triggered_at: new Date().toISOString(),
      });
    }

    const riskScore: RiskScore = {
      user_id: userId,
      score,
      factors,
      last_updated: new Date().toISOString(),
    };

    await this.redis.set(key, JSON.stringify(riskScore));
  }

  async getUserRiskScore(userId: string): Promise<RiskScore | null> {
    const data = await this.redis.get(`risk:user:${userId}`);
    return data ? JSON.parse(data) : null;
  }

  // Alert Management
  async getAlerts(filters?: {
    status?: string;
    severity?: number;
    from?: string;
    to?: string;
  }): Promise<FraudAlert[]> {
    const keys = await this.redis.keys("fraud:alert:*");
    const alerts: FraudAlert[] = [];

    for (const key of keys) {
      const data = await this.redis.get(key);
      if (!data) continue;

      const alert: FraudAlert = JSON.parse(data);

      if (filters?.status && alert.status !== filters.status) continue;
      if (filters?.severity && alert.severity < filters.severity) continue;

      alerts.push(alert);
    }

    return alerts.sort(
      (a, b) =>
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
    );
  }

  async getAlert(id: string): Promise<FraudAlert | null> {
    const data = await this.redis.get(`fraud:alert:${id}`);
    return data ? JSON.parse(data) : null;
  }

  async updateAlertStatus(
    id: string,
    status: FraudAlert["status"],
    resolvedBy?: string,
    notes?: string,
  ): Promise<FraudAlert | null> {
    const alert = await this.getAlert(id);
    if (!alert) return null;

    alert.status = status;

    if (status === "resolved" || status === "false_positive") {
      alert.resolved_at = new Date().toISOString();
    }

    if (resolvedBy) {
      alert.resolved_by = resolvedBy;
    }

    if (notes) {
      alert.notes = notes;
    }

    await this.redis.set(`fraud:alert:${id}`, JSON.stringify(alert));

    return alert;
  }

  // Rule Management
  getRules(): FraudRule[] {
    return Array.from(this.rules.values());
  }

  async updateRule(
    id: string,
    updates: Partial<FraudRule>,
  ): Promise<FraudRule | null> {
    const existing = this.rules.get(id);
    if (!existing) return null;

    const updated = { ...existing, ...updates };
    this.rules.set(id, updated);

    // Persist to Redis
    await this.redis.set(`fraud:rule:${id}`, JSON.stringify(updated));

    return updated;
  }

  async createRule(rule: Omit<FraudRule, "id">): Promise<FraudRule> {
    const id = `custom_${crypto.randomUUID().slice(0, 8)}`;
    const fullRule: FraudRule = { id, ...rule };

    this.rules.set(id, fullRule);
    await this.redis.set(`fraud:rule:${id}`, JSON.stringify(fullRule));

    return fullRule;
  }

  // Statistics
  async getStats() {
    const [totalAlerts, activeAlerts, confirmedFraud, falsePositives] =
      await Promise.all([
        this.redis.keys("fraud:alert:*").then((k) => k.length),
        this.getAlerts({ status: "new" }).then((a) => a.length),
        this.getAlerts({ status: "confirmed" }).then((a) => a.length),
        this.getAlerts({ status: "false_positive" }).then((a) => a.length),
      ]);

    return {
      total_alerts: totalAlerts,
      active_alerts: activeAlerts,
      confirmed_fraud: confirmedFraud,
      false_positives: falsePositives,
      rules_count: this.rules.size,
    };
  }
}

// Fastify API
export async function buildApp(
  fraud: FraudDetectionService,
): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  // Routes
  app.get("/health", async () => ({ status: "ok" }));

  // Evaluate transaction
  const transactionSchema = z.object({
    id: z.string(),
    timestamp: z.string(),
    user_id: z.string(),
    amount: z.number(),
    currency: z.string().default("XOF"),
    type: z.enum(["payment", "transfer", "withdrawal", "refund"]),
    payment_method: z.string().optional(),
    merchant_id: z.string().optional(),
    merchant_category: z.string().optional(),
    location: z.string().optional(),
    ip_address: z.string().optional(),
    device_fingerprint: z.string().optional(),
  });

  app.post<{ Body: z.infer<typeof transactionSchema> }>(
    "/api/v1/fraud/evaluate",
    { schema: { body: transactionSchema } },
    async (request) => {
      const transaction: Transaction = {
        ...request.body,
        status: "pending",
      };

      const { alerts, riskScore } =
        await fraud.evaluateTransaction(transaction);

      // Store alerts
      for (const alert of alerts) {
        await fraud.updateAlertStatus(alert.id, alert.status);
      }

      return {
        transaction_id: transaction.id,
        risk_score: riskScore,
        decision:
          riskScore > 70 ? "block" : riskScore > 40 ? "review" : "approve",
        alerts: alerts.length,
      };
    },
  );

  // Get user risk score
  app.get<{ Params: { userId: string } }>(
    "/api/v1/fraud/risk/:userId",
    async (request) => {
      return fraud.getUserRiskScore(request.params.userId);
    },
  );

  // Alerts
  app.get("/api/v1/fraud/alerts", async (request) => {
    const { status, severity, from, to } = request.query as {
      status?: string;
      severity?: string;
      from?: string;
      to?: string;
    };

    return fraud.getAlerts({
      status,
      severity: severity ? parseInt(severity) : undefined,
      from,
      to,
    });
  });

  app.get<{ Params: { id: string } }>(
    "/api/v1/fraud/alerts/:id",
    async (request) => {
      return fraud.getAlert(request.params.id);
    },
  );

  const alertUpdateSchema = z.object({
    status: z.enum([
      "new",
      "investigating",
      "confirmed",
      "false_positive",
      "resolved",
    ]),
    resolved_by: z.string().optional(),
    notes: z.string().optional(),
  });

  app.patch<{
    Params: { id: string };
    Body: z.infer<typeof alertUpdateSchema>;
  }>(
    "/api/v1/fraud/alerts/:id",
    { schema: { body: alertUpdateSchema } },
    async (request) => {
      const { id } = request.params;
      const { status, resolved_by, notes } = request.body;

      return fraud.updateAlertStatus(id, status, resolved_by, notes);
    },
  );

  // Rules
  app.get("/api/v1/fraud/rules", async () => {
    return fraud.getRules();
  });

  const ruleSchema = z.object({
    name: z.string(),
    description: z.string(),
    type: z.enum([
      "velocity",
      "amount",
      "geographic",
      "device",
      "behavioral",
      "pattern",
    ]),
    parameters: z.record(z.unknown()),
    severity: z.number().min(1).max(10),
    enabled: z.boolean().default(true),
  });

  app.post<{ Body: z.infer<typeof ruleSchema> }>(
    "/api/v1/fraud/rules",
    { schema: { body: ruleSchema } },
    async (request) => {
      return fraud.createRule(request.body);
    },
  );

  app.patch<{
    Params: { id: string };
    Body: Partial<z.infer<typeof ruleSchema>>;
  }>("/api/v1/fraud/rules/:id", async (request) => {
    return fraud.updateRule(request.params.id, request.body);
  });

  // Statistics
  app.get("/api/v1/fraud/stats", async () => {
    return fraud.getStats();
  });

  return app;
}

// Main
async function main() {
  const fraud = new FraudDetectionService();

  const app = await buildApp(fraud);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`Fraud Detection API listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
