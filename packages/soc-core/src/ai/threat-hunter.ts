import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import { z } from "zod";
import pino from "pino";
import crypto from "crypto";

const log = pino({ name: "threat-hunter", level: "info" });

// Configuration
const config = {
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  app: {
    port: parseInt(process.env.PORT || "8091"),
  },
};

// Types
interface HuntCampaign {
  id: string;
  name: string;
  description: string;
  status: "pending" | "running" | "completed" | "failed";
  hypothesis: string;
  techniques: string[];
  startTime?: string;
  endTime?: string;
  findings: Finding[];
  createdAt: string;
}

interface Finding {
  id: string;
  type: "IOC" | "anomaly" | "pattern" | "correlation";
  severity: number;
  description: string;
  evidence: Record<string, unknown>[];
  relatedEntities: string[];
}

interface ThreatPattern {
  id: string;
  name: string;
  description: string;
  pattern: string;
  severity: number;
  mitreTechniques: string[];
  query: string;
  enabled: boolean;
}

interface IOC {
  id: string;
  type: "ip" | "domain" | "hash" | "url" | "email";
  value: string;
  source: string;
  firstSeen: string;
  lastSeen: string;
  tags: string[];
  campaign?: string;
}

// Predefined hunting queries
const HUNTING_QUERIES = {
  lateral_movement: {
    name: "Lateral Movement Detection",
    description: "Detect potential lateral movement patterns",
    techniques: ["T1021", "T1210"],
    query: `
      filter event.action IN ("RDP", "SMB", "SSH", "WinRM")
      AND event.source_ip != event.dest_ip
      AND user.source != user.dest
    `,
  },
  data_exfiltration: {
    name: "Data Exfiltration",
    description: "Detect unusual data transfer patterns",
    techniques: ["T1041", "T1048", "T1567"],
    query: `
      filter bytes_out > 10000000
      AND destination_port NOT IN (80, 443, 22, 3389)
      AND protocol != "DNS"
    `,
  },
  privilege_escalation: {
    name: "Privilege Escalation",
    description: "Detect privilege escalation attempts",
    techniques: ["T1068", "T1548", "T1134"],
    query: `
      filter event.action IN ("sudo", "su", "runas")
      AND user.level CHANGE FROM low TO high
    `,
  },
  persistence: {
    name: "Persistence Mechanisms",
    description: "Detect common persistence techniques",
    techniques: ["T1053", "T1547", "T1136"],
    query: `
      filter event.action IN ("cron", "scheduled_task", "service_create", "registry_write")
      AND location IN ("HKLM", "/etc/cron", "System32")
    `,
  },
  c2_communication: {
    name: "C2 Communication",
    description: "Detect command and control traffic",
    techniques: ["T1071", "T1573", "T1001"],
    query: `
      filter destination_port IN (4444, 5555, 6666, 31337, 8080, 8443)
      OR dns.query IN (malicious_domains)
      OR http.user_agent IN (suspicious_agents)
    `,
  },
  account_compromise: {
    name: "Account Compromise",
    description: "Detect signs of account compromise",
    techniques: ["T1078", "T1114", "T1539"],
    query: `
      filter auth.failures > 5
      OR (auth.success AND location NEW)
      AND session.duration < 60
      AND actions IN (password_change, email_access)
    `,
  },
  ransomware: {
    name: "Ransomware Activity",
    description: "Detect ransomware behavior patterns",
    techniques: ["T1486", "T1490"],
    query: `
      filter file.extension IN (".encrypted", ".locked", ".ransom")
      OR process.name IN (vssadmin, cipher, bitlocker)
      OR filesystem.changes > 1000
    `,
  },
  suspicious_process: {
    name: "Suspicious Process Execution",
    description: "Detect unusual process execution",
    techniques: ["T1059", "T1204", "T1203"],
    query: `
      filter process.parent NOT IN (explorer, cmd, powershell)
      AND process.name IN (powershell.exe, cmd.exe, wscript.exe)
      AND command_line CONTAINS (encoded, frombase64, -enc)
    `,
  },
};

// Threat Hunter Service
class ThreatHunterService {
  private redis: Redis;

  constructor() {
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  // Start a hunt campaign
  async startCampaign(
    name: string,
    description: string,
    hypothesis: string,
    techniques: string[],
  ): Promise<HuntCampaign> {
    const id = crypto.randomUUID();

    const campaign: HuntCampaign = {
      id,
      name,
      description,
      hypothesis,
      techniques,
      status: "running",
      findings: [],
      createdAt: new Date().toISOString(),
    };

    await this.redis.set(`campaign:${id}`, JSON.stringify(campaign));

    // Run the hunt in background
    this.runHunt(campaign).catch((err) => {
      log.error({ error: err, campaignId: id }, "Hunt failed");
      this.updateCampaignStatus(id, "failed");
    });

    return campaign;
  }

  private async runHunt(campaign: HuntCampaign) {
    const startTime = new Date().toISOString();

    // Simulate hunting by running queries
    const findings: Finding[] = [];

    // Example: Run lateral movement query
    const lateralMovementResults = await this.runQuery(
      HUNTING_QUERIES.lateral_movement.query,
    );
    if (lateralMovementResults.length > 0) {
      findings.push({
        id: crypto.randomUUID(),
        type: "pattern",
        severity: 8,
        description: "Potential lateral movement detected",
        evidence: lateralMovementResults.slice(0, 5),
        relatedEntities: lateralMovementResults
          .map((r: any) => r.source_ip)
          .slice(0, 10),
      });
    }

    // Run other queries based on techniques
    for (const technique of campaign.techniques) {
      const matchingQuery = Object.values(HUNTING_QUERIES).find((q) =>
        q.techniques.includes(technique),
      );

      if (matchingQuery) {
        const results = await this.runQuery(matchingQuery.query);
        if (results.length > 0) {
          findings.push({
            id: crypto.randomUUID(),
            type: "correlation",
            severity: 7,
            description: `Pattern match for technique ${technique}`,
            evidence: results.slice(0, 3),
            relatedEntities: [],
          });
        }
      }
    }

    // Add some random findings for demo
    if (findings.length === 0) {
      findings.push({
        id: crypto.randomUUID(),
        type: "anomaly",
        severity: 5,
        description: "No significant findings - environment appears clean",
        evidence: [],
        relatedEntities: [],
      });
    }

    // Update campaign
    campaign.findings = findings;
    campaign.status = "completed";
    campaign.endTime = new Date().toISOString();

    await this.redis.set(`campaign:${campaign.id}`, JSON.stringify(campaign));

    log.info(
      { campaignId: campaign.id, findings: findings.length },
      "Hunt completed",
    );
  }

  private async runQuery(query: string): Promise<Record<string, unknown>[]> {
    // In production, this would execute against Elasticsearch/SIEM
    // For now, return simulated results
    if (Math.random() > 0.7) {
      return [
        {
          source_ip: "192.168.1.100",
          dest_ip: "10.0.0.5",
          user: "admin",
          timestamp: new Date().toISOString(),
        },
        {
          source_ip: "192.168.1.101",
          dest_ip: "10.0.0.10",
          user: "jdoe",
          timestamp: new Date().toISOString(),
        },
      ];
    }
    return [];
  }

  private async updateCampaignStatus(
    id: string,
    status: HuntCampaign["status"],
  ) {
    const data = await this.redis.get(`campaign:${id}`);
    if (data) {
      const campaign = JSON.parse(data) as HuntCampaign;
      campaign.status = status;
      if (status === "completed" || status === "failed") {
        campaign.endTime = new Date().toISOString();
      }
      await this.redis.set(`campaign:${id}`, JSON.stringify(campaign));
    }
  }

  // Get campaign
  async getCampaign(id: string): Promise<HuntCampaign | null> {
    const data = await this.redis.get(`campaign:${id}`);
    return data ? JSON.parse(data) : null;
  }

  // List campaigns
  async listCampaigns(): Promise<HuntCampaign[]> {
    const keys = await this.redis.keys("campaign:*");
    const campaigns: HuntCampaign[] = [];

    for (const key of keys) {
      const data = await this.redis.get(key);
      if (data) campaigns.push(JSON.parse(data));
    }

    return campaigns.sort(
      (a, b) =>
        new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
    );
  }

  // Get predefined patterns
  getPatterns(): ThreatPattern[] {
    return Object.entries(HUNTING_QUERIES).map(([key, value], index) => ({
      id: key,
      name: value.name,
      description: value.description,
      pattern: value.query,
      severity: 7,
      mitreTechniques: value.techniques,
      query: value.query,
      enabled: true,
    }));
  }

  // IOC Management
  async addIOC(ioc: Omit<IOC, "id">): Promise<IOC> {
    const id = crypto.randomUUID();
    const fullIOC: IOC = { id, ...ioc };

    await this.redis.hset("iocs", ioc.value, JSON.stringify(fullIOC));
    await this.redis.sadd("iocs:by_type", ioc.type);
    await this.redis.sadd("iocs:by_source", ioc.source);

    return fullIOC;
  }

  async getIOC(value: string): Promise<IOC | null> {
    const data = await this.redis.hget("iocs", value);
    return data ? JSON.parse(data) : null;
  }

  async searchIOCs(query: string, type?: string): Promise<IOC[]> {
    const allIOCs = await this.redis.hgetall("iocs");
    const results: IOC[] = [];

    for (const [value, data] of Object.entries(allIOCs)) {
      if (value.includes(query) || query === "*") {
        const ioc = JSON.parse(data) as IOC;
        if (!type || ioc.type === type) {
          results.push(ioc);
        }
      }
    }

    return results;
  }

  // Auto-hunt: Scheduled threat hunting
  async runAutoHunt() {
    log.info("Starting automated threat hunt");

    const campaigns = await this.listCampaigns();
    const runningCampaigns = campaigns.filter((c) => c.status === "running");

    if (runningCampaigns.length > 0) {
      log.info(
        { count: runningCampaigns.length },
        "Skipping - campaigns already running",
      );
      return;
    }

    // Start campaigns for critical patterns
    const criticalPatterns = [
      "ransomware",
      "c2_communication",
      "data_exfiltration",
    ];

    for (const pattern of criticalPatterns) {
      const query = HUNTING_QUERIES[pattern as keyof typeof HUNTING_QUERIES];
      if (query) {
        await this.startCampaign(
          `Auto Hunt: ${query.name}`,
          query.description,
          `Hypothesis: ${query.description}`,
          query.techniques,
        );
      }
    }
  }

  // Statistics
  async getStats() {
    const campaigns = await this.listCampaigns();
    const iocs = await this.redis.hlen("iocs");

    return {
      total_campaigns: campaigns.length,
      completed_campaigns: campaigns.filter((c) => c.status === "completed")
        .length,
      running_campaigns: campaigns.filter((c) => c.status === "running").length,
      total_findings: campaigns.reduce((sum, c) => sum + c.findings.length, 0),
      iocs_indexed: iocs,
      patterns_available: Object.keys(HUNTING_QUERIES).length,
    };
  }
}

// Fastify API
export async function buildApp(
  hunter: ThreatHunterService,
): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  // Routes
  app.get("/health", async () => ({ status: "ok" }));

  // Start campaign
  const campaignSchema = z.object({
    name: z.string(),
    description: z.string(),
    hypothesis: z.string(),
    techniques: z.array(z.string()),
  });

  app.post<{ Body: z.infer<typeof campaignSchema> }>(
    "/api/v1/hunt/campaigns",
    { schema: { body: campaignSchema } },
    async (request) => {
      return hunter.startCampaign(
        request.body.name,
        request.body.description,
        request.body.hypothesis,
        request.body.techniques,
      );
    },
  );

  // Get campaign
  app.get<{ Params: { id: string } }>(
    "/api/v1/hunt/campaigns/:id",
    async (request) => {
      return hunter.getCampaign(request.params.id);
    },
  );

  // List campaigns
  app.get("/api/v1/hunt/campaigns", async () => {
    return hunter.listCampaigns();
  });

  // Get patterns
  app.get("/api/v1/hunt/patterns", async () => {
    return hunter.getPatterns();
  });

  // Run pattern
  app.post<{ Body: { patternId: string } }>(
    "/api/v1/hunt/patterns/:patternId/run",
    async (request) => {
      const pattern = hunter
        .getPatterns()
        .find((p) => p.id === request.body.patternId);
      if (!pattern) {
        return { error: "Pattern not found" };
      }

      return hunter.startCampaign(
        `Manual Hunt: ${pattern.name}`,
        pattern.description,
        `Hypothesis: ${pattern.description}`,
        pattern.mitreTechniques,
      );
    },
  );

  // IOC Management
  app.post("/api/v1/hunt/iocs", async (request) => {
    const ioc = request.body as Omit<IOC, "id">;
    return hunter.addIOC(ioc);
  });

  app.get<{ Querystring: { q?: string; type?: string } }>(
    "/api/v1/hunt/iocs",
    async (request) => {
      return hunter.searchIOCs(request.query.q || "*", request.query.type);
    },
  );

  // Auto hunt
  app.post("/api/v1/hunt/auto", async () => {
    await hunter.runAutoHunt();
    return { status: "Auto hunt started" };
  });

  // Statistics
  app.get("/api/v1/hunt/stats", async () => {
    return hunter.getStats();
  });

  return app;
}

// Main
async function main() {
  const hunter = new ThreatHunterService();

  const app = await buildApp(hunter);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`Threat Hunter API listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
