import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import { z } from "zod";
import pino from "pino";
import crypto from "crypto";

const log = pino({ name: "threat-intel", level: "info" });

// Configuration
const config = {
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  app: {
    port: parseInt(process.env.PORT || "8081"),
  },
};

// Types
interface Indicator {
  id: string;
  type: "ip" | "domain" | "hash" | "url" | "email";
  value: string;
  reputation: "malicious" | "suspicious" | "clean" | "unknown";
  confidence: number;
  sources: string[];
  tags: string[];
  firstSeen?: string;
  lastSeen?: string;
  metadata?: Record<string, unknown>;
}

interface ThreatActor {
  id: string;
  name: string;
  aliases: string[];
  description: string;
  motivation: string;
  targetSectors: string[];
  ttps: string[];
  lastActivity?: string;
}

interface CVE {
  id: string;
  description: string;
  severity: number;
  published: string;
  affectedProducts: string[];
  references: string[];
  mitigation?: string;
}

// Threat Intelligence Service
class ThreatIntelService {
  private redis: Redis;

  constructor() {
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  // Indicator Management
  async addIndicator(indicator: Omit<Indicator, "id">): Promise<Indicator> {
    const id = crypto.randomUUID();
    const fullIndicator: Indicator = { id, ...indicator };

    // Store in Redis
    await this.redis.hset(
      `indicators:${indicator.type}`,
      indicator.value,
      JSON.stringify(fullIndicator),
    );
    await this.redis.sadd(`indicators:types`, indicator.type);

    // Add to sorted set for reputation scoring
    if (indicator.reputation === "malicious") {
      await this.redis.zadd("threat_scores", Date.now(), indicator.value);
    }

    log.info({ indicator: indicator.value }, "Indicator added");
    return fullIndicator;
  }

  async getIndicator(type: string, value: string): Promise<Indicator | null> {
    const cached = await this.redis.hget(`indicators:${type}`, value);
    return cached ? JSON.parse(cached) : null;
  }

  async searchIndicators(query: string, type?: string): Promise<Indicator[]> {
    const types = type ? [type] : await this.redis.smembers("indicators:types");
    const results: Indicator[] = [];

    for (const t of types) {
      const keys = await this.redis.hkeys(`indicators:${t}`);
      for (const key of keys) {
        if (key.includes(query)) {
          const indicator = await this.redis.hget(`indicators:${t}`, key);
          if (indicator) {
            results.push(JSON.parse(indicator));
          }
        }
      }
    }

    return results;
  }

  // External Threat Feeds
  async fetchFromMISP(
    mispUrl: string,
    apiKey: string,
    query: string,
  ): Promise<Indicator[]> {
    // In production, implement actual MISP API call
    // const response = await fetch(`${mispUrl}/attributes/restSearch`, {
    //   headers: { "Authorization": apiKey, "Content-Type": "application/json" },
    //   body: JSON.stringify({ returnFormat: "json", value: query })
    // })
    log.info({ mispUrl, query }, "Fetching from MISP");
    return [];
  }

  async fetchFromVirusTotal(
    ip: string,
    apiKey: string,
  ): Promise<Partial<Indicator>> {
    // In production, implement actual VT API call
    // const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
    //   headers: { "x-apikey": apiKey }
    // })
    log.info({ ip }, "Fetching from VirusTotal");
    return {};
  }

  async checkReputation(indicator: string, type: string): Promise<Indicator> {
    // Check local cache first
    const local = await this.getIndicator(type, indicator);
    if (local) {
      return local;
    }

    // Query external sources
    const sources: Partial<Indicator>[] = [];

    // MISP (if configured)
    const mispUrl = process.env.MISP_URL;
    const mispKey = process.env.MISP_API_KEY;
    if (mispUrl && mispKey) {
      const mispResult = await this.fetchFromMISP(mispUrl, mispKey, indicator);
      sources.push(...mispResult);
    }

    // VirusTotal (if configured)
    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    if (vtKey && type === "ip") {
      const vtResult = await this.fetchFromVirusTotal(indicator, vtKey);
      sources.push(vtResult);
    }

    // Aggregate results
    const maliciousCount = sources.filter(
      (s) => s.reputation === "malicious",
    ).length;
    const confidence =
      sources.length > 0 ? (maliciousCount / sources.length) * 100 : 0;

    const result: Indicator = {
      id: crypto.randomUUID(),
      type: type as Indicator["type"],
      value: indicator,
      reputation:
        confidence > 50
          ? "malicious"
          : confidence > 20
            ? "suspicious"
            : "unknown",
      confidence,
      sources: sources.map((s) => s.sources || []).flat(),
      tags: sources.map((s) => s.tags || []).flat(),
    };

    // Cache result
    if (sources.length > 0) {
      await this.addIndicator(result);
    }

    return result;
  }

  // CVE Management
  async addCVE(cve: CVE): Promise<void> {
    await this.redis.hset("cves", cve.id, JSON.stringify(cve));

    // Add to severity sorted set
    await this.redis.zadd("cve:severity", cve.severity, cve.id);

    log.info({ cve: cve.id }, "CVE added");
  }

  async getCVE(id: string): Promise<CVE | null> {
    const cached = await this.redis.hget("cves", id);
    return cached ? JSON.parse(cached) : null;
  }

  async getRecentCVEs(days: number = 7): Promise<CVE[]> {
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
    const keys = await this.redis.zrangebyscore("cve:severity", cutoff, "+inf");

    const cves: CVE[] = [];
    for (const key of keys.slice(0, 50)) {
      const cve = await this.getCVE(key);
      if (cve) cves.push(cve);
    }

    return cves;
  }

  async searchCVEs(query: string): Promise<CVE[]> {
    const allCves = await this.redis.hvals("cves");
    const parsed = allCves.map((c) => JSON.parse(c));
    return parsed.filter(
      (c) =>
        c.id.toLowerCase().includes(query.toLowerCase()) ||
        c.description.toLowerCase().includes(query.toLowerCase()),
    );
  }

  // Threat Actors
  async addThreatActor(actor: Omit<ThreatActor, "id">): Promise<ThreatActor> {
    const id = crypto.randomUUID();
    const fullActor: ThreatActor = { id, ...actor };
    await this.redis.hset("threat_actors", id, JSON.stringify(fullActor));
    return fullActor;
  }

  async getThreatActors(filters?: {
    motivation?: string;
    targetSector?: string;
  }): Promise<ThreatActor[]> {
    const allActors = await this.redis.hvals("threat_actors");
    let actors = allActors.map((a) => JSON.parse(a));

    if (filters?.motivation) {
      actors = actors.filter((a) => a.motivation === filters.motivation);
    }
    if (filters?.targetSector) {
      actors = actors.filter((a) =>
        a.targetSectors.includes(filters.targetSector!),
      );
    }

    return actors;
  }

  // Statistics
  async getStats() {
    const [indicatorCount, cveCount, actorCount] = await Promise.all([
      this.redis.scard("indicators:types"),
      this.redis.zcard("cve:severity"),
      this.redis.hlen("threat_actors"),
    ]);

    return {
      indicators: indicatorCount,
      cves: cveCount,
      threat_actors: actorCount,
    };
  }
}

// Fastify API
export async function buildApp(
  threatIntel: ThreatIntelService,
): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  // Routes
  app.get("/health", async () => ({ status: "ok" }));

  // Indicators
  const indicatorSchema = z.object({
    type: z.enum(["ip", "domain", "hash", "url", "email"]),
    value: z.string(),
    reputation: z.enum(["malicious", "suspicious", "clean", "unknown"]),
    confidence: z.number().min(0).max(100),
    sources: z.array(z.string()),
    tags: z.array(z.string()),
    metadata: z.record(z.unknown()).optional(),
  });

  app.post<{ Body: z.infer<typeof indicatorSchema> }>(
    "/api/v1/threat-intel/indicators",
    { schema: { body: indicatorSchema } },
    async (request) => {
      return threatIntel.addIndicator(request.body);
    },
  );

  app.get<{ Params: { type: string }; Querystring: { value: string } }>(
    "/api/v1/threat-intel/indicators/:type",
    async (request) => {
      const { type } = request.params;
      const { value } = request.query;
      if (value) {
        return threatIntel.getIndicator(type, value);
      }
      return { error: "value query parameter required" };
    },
  );

  app.get<{ Querystring: { q: string; type?: string } }>(
    "/api/v1/threat-intel/search",
    async (request) => {
      const { q, type } = request.query;
      return threatIntel.searchIndicators(q, type);
    },
  );

  app.get<{ Params: { type: string }; Querystring: { value: string } }>(
    "/api/v1/threat-intel/check/:type",
    async (request) => {
      const { type } = request.params;
      const { value } = request.query;
      return threatIntel.checkReputation(value, type);
    },
  );

  // CVEs
  app.get("/api/v1/threat-intel/cves/recent", async (request) => {
    const { days } = request.query as { days?: string };
    return threatIntel.getRecentCVEs(days ? parseInt(days) : 7);
  });

  app.get<{ Params: { id: string } }>(
    "/api/v1/threat-intel/cves/:id",
    async (request) => {
      return threatIntel.getCVE(request.params.id);
    },
  );

  app.get<{ Querystring: { q: string } }>(
    "/api/v1/threat-intel/cves/search",
    async (request) => {
      return threatIntel.searchCVEs(request.query.q);
    },
  );

  // Threat Actors
  app.get("/api/v1/threat-intel/actors", async (request) => {
    const { motivation, target_sector } = request.query as {
      motivation?: string;
      target_sector?: string;
    };
    return threatIntel.getThreatActors({
      motivation: target_sector,
      targetSector: target_sector,
    });
  });

  // Stats
  app.get("/api/v1/threat-intel/stats", async () => {
    return threatIntel.getStats();
  });

  return app;
}

// Main
async function main() {
  const threatIntel = new ThreatIntelService();

  // Seed some demo data
  await threatIntel.addIndicator({
    type: "ip",
    value: "192.168.1.100",
    reputation: "malicious",
    confidence: 95,
    sources: ["misp", "internal"],
    tags: ["c2", "botnet"],
  });

  await threatIntel.addThreatActor({
    name: "APT42",
    aliases: ["Lazarus", "Hidden Cobra"],
    description: "North Korean state-sponsored threat actor",
    motivation: "financial",
    targetSectors: ["finance", "government"],
    ttps: ["T1566", "T1041"],
  });

  const app = await buildApp(threatIntel);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`Threat Intel API listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
