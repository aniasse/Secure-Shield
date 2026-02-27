import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import pino from "pino";
import crypto from "crypto";

const log = pino({ name: "cyber-agent", level: "info" });

const config = {
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  app: {
    port: parseInt(process.env.PORT || "8095"),
  },
  agent: {
    scanInterval: parseInt(process.env.SCAN_INTERVAL || "30000"),
    autoBlock: process.env.AUTO_BLOCK === "true",
    threatThreshold: parseInt(process.env.THRESHOLD || "70"),
  },
};

interface NetworkEvent {
  id: string;
  timestamp: string;
  sourceIp: string;
  destIp: string;
  port: number;
  protocol: string;
  action: string;
  bytes: number;
  metadata?: Record<string, unknown>;
}

interface ThreatIntelligence {
  indicator: string;
  type: "ip" | "domain" | "hash" | "url";
  reputation: "malicious" | "suspicious" | "clean";
  confidence: number;
  source: string;
  firstSeen: string;
  lastSeen: string;
}

interface DefenseAction {
  id: string;
  type: "block_ip" | "quarantine" | "alert" | "isolate" | "rate_limit";
  target: string;
  reason: string;
  severity: number;
  executedAt: string;
  status: "pending" | "executed" | "failed" | "rolled_back";
  automated: boolean;
}

interface AgentState {
  status: "idle" | "monitoring" | "investigating" | "responding" | "error";
  threatsDetected: number;
  defensesExecuted: number;
  uptime: number;
  lastScan: string;
  memory: string[];
}

interface SecurityMetric {
  metric: string;
  value: number;
  timestamp: string;
  trend: "up" | "down" | "stable";
}

class CyberAgent {
  private redis: Redis;
  private state: AgentState;
  private isRunning: boolean;
  private scanInterval: NodeJS.Timeout | null;

  constructor() {
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
    this.isRunning = false;
    this.scanInterval = null;
    this.state = {
      status: "idle",
      threatsDetected: 0,
      defensesExecuted: 0,
      uptime: Date.now(),
      lastScan: new Date().toISOString(),
      memory: [],
    };
  }

  async start(): Promise<void> {
    log.info("Starting Cyber Agent...");
    this.isRunning = true;
    this.state.status = "monitoring";

    await this.redis.set("agent:status", "monitoring");

    this.scanInterval = setInterval(async () => {
      await this.continuousMonitoring();
    }, config.agent.scanInterval);

    log.info("Cyber Agent started successfully");
  }

  async stop(): Promise<void> {
    log.info("Stopping Cyber Agent...");
    this.isRunning = false;
    if (this.scanInterval) {
      clearInterval(this.scanInterval);
      this.scanInterval = null;
    }
    this.state.status = "idle";
    await this.redis.set("agent:status", "idle");
    log.info("Cyber Agent stopped");
  }

  async continuousMonitoring(): Promise<void> {
    if (!this.isRunning) return;

    this.state.status = "monitoring";
    this.state.lastScan = new Date().toISOString();

    try {
      await Promise.all([
        this.scanNetworkTraffic(),
        this.checkThreatIntel(),
        this.analyzeBehavioralAnomalies(),
        this.updateMetrics(),
      ]);

      await this.predictiveDefense();
      this.learnFromPattern();
    } catch (error) {
      log.error({ error }, "Monitoring cycle failed");
      this.state.status = "error";
    }
  }

  private async scanNetworkTraffic(): Promise<void> {
    const suspiciousPatterns = [
      {
        pattern: "port_scan",
        regex: /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/,
        risk: 60,
      },
      {
        pattern: "ddos_signature",
        regex: /flood|burst|amplification/i,
        risk: 85,
      },
      {
        pattern: "data_exfiltration",
        regex: /exfil|upload|large.*outbound/i,
        risk: 90,
      },
      {
        pattern: "lateral_movement",
        regex: /psexec|wmi|smb|rdp.*brute/i,
        risk: 80,
      },
    ];

    const recentEvents = await this.redis.lrange("network:events", 0, 99);

    for (const eventData of recentEvents) {
      const event: NetworkEvent = JSON.parse(eventData);

      for (const { pattern, regex, risk } of suspiciousPatterns) {
        if (
          regex.test(event.action) ||
          regex.test((event.metadata?.description as string) || "")
        ) {
          await this.detectThreat(event, pattern, risk);
        }
      }
    }
  }

  private async checkThreatIntel(): Promise<void> {
    const maliciousIPs = await this.redis.zrangebyscore(
      "threat_scores",
      Date.now() - 3600000,
      Date.now(),
    );

    for (const ip of maliciousIPs) {
      const cached = await this.redis.get(`defense:ip:${ip}`);
      if (!cached && config.agent.autoBlock) {
        await this.executeDefense({
          type: "block_ip",
          target: ip,
          reason: "Known malicious IP from threat intelligence",
          severity: 85,
        });
      }
    }
  }

  private async analyzeBehavioralAnomalies(): Promise<void> {
    const baselines = await this.redis.hgetall("metrics:baseline");

    for (const [metric, baselineValue] of Object.entries(baselines)) {
      const currentValue = await this.redis.get(`metrics:current:${metric}`);
      if (!currentValue) continue;

      const current = parseFloat(currentValue);
      const baseline = parseFloat(baselineValue as string);
      const deviation = Math.abs((current - baseline) / baseline) * 100;

      if (deviation > 50) {
        await this.detectThreat(
          {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            sourceIp: "unknown",
            destIp: "unknown",
            port: 0,
            protocol: "unknown",
            action: "anomaly",
            bytes: 0,
          } as NetworkEvent,
          `anomaly:${metric}`,
          Math.min(deviation, 100),
        );
      }
    }
  }

  private async detectThreat(
    event: NetworkEvent,
    type: string,
    severity: number,
  ): Promise<void> {
    if (severity < config.agent.threatThreshold) return;

    this.state.threatsDetected++;
    const threatId = crypto.randomUUID();

    const threat = {
      id: threatId,
      event,
      type,
      severity,
      detectedAt: new Date().toISOString(),
      status: "detected",
    };

    await this.redis.set(`threat:${threatId}`, JSON.stringify(threat));
    await this.redis.lpush("threats:recent", threatId);
    await this.redis.ltrim("threats:recent", 0, 999);

    await this.redis.incr("agent:threats:total");

    this.state.memory.push(`Detected: ${type} with severity ${severity}`);

    if (this.state.memory.length > 100) {
      this.state.memory.shift();
    }

    log.warn({ threatId, type, severity }, "Threat detected");

    if (severity > 75 && config.agent.autoBlock) {
      await this.executeDefense({
        type: event.sourceIp !== "unknown" ? "block_ip" : "alert",
        target: event.sourceIp !== "unknown" ? event.sourceIp : "unknown",
        reason: `Automated response to ${type}`,
        severity,
      });
    }
  }

  async executeDefense(
    action: Omit<DefenseAction, "id" | "executedAt" | "status">,
  ): Promise<DefenseAction> {
    this.state.status = "responding";
    this.state.defensesExecuted++;

    const defense: DefenseAction = {
      id: crypto.randomUUID(),
      ...action,
      executedAt: new Date().toISOString(),
      status: "pending",
      automated: true,
    };

    try {
      switch (action.type) {
        case "block_ip":
          await this.blockIP(action.target);
          break;
        case "quarantine":
          await this.quarantineHost(action.target);
          break;
        case "isolate":
          await this.isolateNetwork(action.target);
          break;
        case "rate_limit":
          await this.applyRateLimit(action.target);
          break;
        case "alert":
          await this.sendAlert(action);
          break;
      }

      defense.status = "executed";
      await this.redis.set(`defense:${defense.id}`, JSON.stringify(defense));
      await this.redis.lpush("defenses:executed", defense.id);

      this.state.memory.push(`Executed: ${action.type} on ${action.target}`);
      log.info({ defense }, "Defense action executed");
    } catch (error) {
      defense.status = "failed";
      log.error({ error, defense }, "Defense action failed");
    }

    this.state.status = "monitoring";
    return defense;
  }

  private async blockIP(ip: string): Promise<void> {
    if (ip === "unknown" || ip === "0.0.0.0") return;

    await this.redis.set(
      `blocked:ip:${ip}`,
      JSON.stringify({
        blockedAt: new Date().toISOString(),
        reason: "Automated block by cyber agent",
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      }),
    );

    await this.redis.sadd("blocked:ips", ip);
    log.info({ ip }, "IP blocked");
  }

  private async quarantineHost(hostname: string): Promise<void> {
    await this.redis.set(
      `quarantine:host:${hostname}`,
      JSON.stringify({
        quarantinedAt: new Date().toISOString(),
        reason: "Automated quarantine by cyber agent",
      }),
    );
    log.info({ hostname }, "Host quarantined");
  }

  private async isolateNetwork(target: string): Promise<void> {
    await this.redis.set(
      `isolated:target:${target}`,
      JSON.stringify({
        isolatedAt: new Date().toISOString(),
        reason: "Automated isolation by cyber agent",
      }),
    );
    log.info({ target }, "Target isolated from network");
  }

  private async applyRateLimit(target: string): Promise<void> {
    await this.redis.set(
      `ratelimit:target:${target}`,
      JSON.stringify({
        limitedAt: new Date().toISOString(),
        maxRequests: 10,
        windowSeconds: 60,
      }),
    );
    log.info({ target }, "Rate limit applied");
  }

  private async sendAlert(action: DefenseAction): Promise<void> {
    await this.redis.publish(
      "alerts",
      JSON.stringify({
        type: "security_alert",
        action,
        timestamp: new Date().toISOString(),
      }),
    );
  }

  private async predictiveDefense(): Promise<void> {
    const recentThreats = await this.redis.lrange("threats:recent", 0, 9);

    if (recentThreats.length < 3) return;

    const patterns = await this.analyzeAttackPatterns(recentThreats);

    for (const pattern of patterns) {
      if (pattern.frequency > 5 && !pattern.mitigated) {
        await this.executeDefense({
          type: "rate_limit",
          target: pattern.indicator,
          reason: `Predictive defense: ${pattern.type} pattern detected`,
          severity: 70,
        });

        pattern.mitigated = true;
      }
    }
  }

  private async analyzeAttackPatterns(
    threatIds: string[],
  ): Promise<
    Array<{
      type: string;
      indicator: string;
      frequency: number;
      mitigated: boolean;
    }>
  > {
    const patterns: Map<
      string,
      { type: string; indicator: string; frequency: number; mitigated: boolean }
    > = new Map();

    for (const threatId of threatIds) {
      const threatData = await this.redis.get(`threat:${threatId}`);
      if (!threatData) continue;

      const threat = JSON.parse(threatData);
      const key = `${threat.event.sourceIp}:${threat.type}`;

      if (!patterns.has(key)) {
        patterns.set(key, {
          type: threat.type,
          indicator: threat.event.sourceIp,
          frequency: 0,
          mitigated: false,
        });
      }

      const pattern = patterns.get(key)!;
      pattern.frequency++;
    }

    return Array.from(patterns.values());
  }

  private async updateMetrics(): Promise<void> {
    const metrics: SecurityMetric[] = [
      {
        metric: "threats_detected",
        value: this.state.threatsDetected,
        timestamp: new Date().toISOString(),
        trend: "stable",
      },
      {
        metric: "defenses_executed",
        value: this.state.defensesExecuted,
        timestamp: new Date().toISOString(),
        trend: "stable",
      },
      {
        metric: "blocked_ips",
        value: await this.redis.scard("blocked:ips"),
        timestamp: new Date().toISOString(),
        trend: "up",
      },
      {
        metric: "quarantined_hosts",
        value: await this.redis.keys("quarantine:host:*").then((k) => k.length),
        timestamp: new Date().toISOString(),
        trend: "stable",
      },
    ];

    for (const metric of metrics) {
      await this.redis.set(
        `metrics:current:${metric.metric}`,
        metric.value.toString(),
      );
    }
  }

  private learnFromPattern(): void {
    if (this.state.memory.length < 5) return;

    const recent = this.state.memory.slice(-10);
    log.info({ memory: recent }, "Agent learning from recent events");
  }

  async getState(): Promise<AgentState> {
    return {
      ...this.state,
      uptime: Date.now() - this.state.uptime,
    };
  }

  async getThreats(limit = 20): Promise<unknown[]> {
    const threatIds = await this.redis.lrange("threats:recent", 0, limit - 1);
    const threats = [];

    for (const id of threatIds) {
      const data = await this.redis.get(`threat:${id}`);
      if (data) threats.push(JSON.parse(data));
    }

    return threats;
  }

  async getDefenses(limit = 20): Promise<unknown[]> {
    const defenseIds = await this.redis.lrange(
      "defenses:executed",
      0,
      limit - 1,
    );
    const defenses = [];

    for (const id of defenseIds) {
      const data = await this.redis.get(`defense:${id}`);
      if (data) defenses.push(JSON.parse(data));
    }

    return defenses;
  }

  async getMetrics(): Promise<Record<string, unknown>> {
    const [blockedCount, quarantineCount, threatCount] = await Promise.all([
      this.redis.scard("blocked:ips"),
      this.redis.keys("quarantine:host:*").then((k) => k.length),
      this.redis.llen("threats:recent"),
    ]);

    return {
      blockedIPs: blockedCount,
      quarantinedHosts: quarantineCount,
      recentThreats: threatCount,
      uptime: Date.now() - this.state.uptime,
      status: this.state.status,
    };
  }

  async runDiagnostic(): Promise<{
    redis: boolean;
    memory: number;
    blockedIps: number;
    threats: number;
    recommendations: string[];
  }> {
    const recommendations: string[] = [];

    const blockedIps = await this.redis.scard("blocked:ips");
    const threats = await this.redis.llen("threats:recent");
    const memoryUsage = process.memoryUsage();

    if (blockedIps > 100) {
      recommendations.push(
        "Consider reviewing blocked IPs - high count detected",
      );
    }

    if (threats > 50) {
      recommendations.push(
        "High threat activity - consider adjusting detection thresholds",
      );
    }

    if (memoryUsage.heapUsed > 500 * 1024 * 1024) {
      recommendations.push(
        "High memory usage detected - consider restarting agent",
      );
    }

    recommendations.push("Continuous monitoring active");

    return {
      redis: true,
      memory: Math.round(memoryUsage.heapUsed / 1024 / 1024),
      blockedIps,
      threats,
      recommendations,
    };
  }
}

export async function buildApp(agent: CyberAgent): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  app.get("/health", async () => ({ status: "ok", agent: "cyber-agent" }));

  app.get("/api/v1/agent/status", async () => {
    return agent.getState();
  });

  app.get("/api/v1/agent/threats", async (request) => {
    const limit = Number(request.query["limit"] || 20);
    return agent.getThreats(limit);
  });

  app.get("/api/v1/agent/defenses", async (request) => {
    const limit = Number(request.query["limit"] || 20);
    return agent.getDefenses(limit);
  });

  app.get("/api/v1/agent/metrics", async () => {
    return agent.getMetrics();
  });

  app.post("/api/v1/agent/start", async () => {
    await agent.start();
    return { status: "started" };
  });

  app.post("/api/v1/agent/stop", async () => {
    await agent.stop();
    return { status: "stopped" };
  });

  app.post("/api/v1/agent/defense", async (request) => {
    const { type, target, reason, severity } = request.body as {
      type: "block_ip" | "quarantine" | "isolate" | "rate_limit" | "alert";
      target: string;
      reason: string;
      severity: number;
    };
    return agent.executeDefense({ type, target, reason, severity });
  });

  app.get("/api/v1/agent/diagnostic", async () => {
    return agent.runDiagnostic();
  });

  return app;
}

async function main() {
  const agent = new CyberAgent();

  const app = await buildApp(agent);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  await agent.start();

  log.info(`Cyber Agent API listening on port ${config.app.port}`);
  log.info("Agent started - monitoring and defending the network");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
