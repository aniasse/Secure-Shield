import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import { z } from "zod";
import pino from "pino";
import crypto from "crypto";
import fs from "fs/promises";
import path from "path";

const log = pino({ name: "reports", level: "info" });

// Configuration
const config = {
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  app: {
    port: parseInt(process.env.PORT || "8088"),
  },
};

// Types
interface Report {
  id: string;
  type:
    | "daily"
    | "weekly"
    | "monthly"
    | "incident"
    | "compliance"
    | "executive";
  name: string;
  period_start: string;
  period_end: string;
  status: "generating" | "completed" | "failed";
  created_at: string;
  completed_at?: string;
  format: "pdf" | "html" | "json";
  download_url?: string;
  metadata?: Record<string, unknown>;
}

interface ReportSection {
  id: string;
  title: string;
  content: Record<string, unknown>;
  order: number;
}

interface DailyStats {
  date: string;
  total_alerts: number;
  critical_alerts: number;
  resolved_alerts: number;
  events_processed: number;
  avg_response_time: number;
  top_threats: Array<{ name: string; count: number }>;
  affected_assets: string[];
}

interface IncidentReport {
  incident_id: string;
  title: string;
  timeline: Array<{ timestamp: string; action: string; actor: string }>;
  root_cause: string;
  impact: string;
  recommendations: string[];
}

// Report Generation Service
class ReportService {
  private redis: Redis;

  constructor() {
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  // Create report request
  async createReport(
    type: Report["type"],
    periodStart: string,
    periodEnd: string,
    format: Report["format"],
    name?: string,
    metadata?: Record<string, unknown>,
  ): Promise<Report> {
    const id = crypto.randomUUID();

    const report: Report = {
      id,
      type,
      name: name || `${type} report`,
      period_start: periodStart,
      period_end: periodEnd,
      status: "generating",
      created_at: new Date().toISOString(),
      format,
      metadata,
    };

    await this.redis.set(`report:${id}`, JSON.stringify(report));

    // Start async generation
    this.generateReport(report).catch((err) => {
      log.error({ error: err, reportId: id }, "Report generation failed");
      this.updateReportStatus(id, "failed");
    });

    return report;
  }

  private async updateReportStatus(id: string, status: Report["status"]) {
    const report = await this.getReport(id);
    if (report) {
      report.status = status;
      if (status === "completed") {
        report.completed_at = new Date().toISOString();
        report.download_url = `/api/v1/reports/${id}/download`;
      }
      await this.redis.set(`report:${id}`, JSON.stringify(report));
    }
  }

  private async generateReport(report: Report) {
    try {
      let content: Record<string, unknown>;

      switch (report.type) {
        case "daily":
          content = await this.generateDailyReport(report);
          break;
        case "weekly":
          content = await this.generateWeeklyReport(report);
          break;
        case "monthly":
          content = await this.generateMonthlyReport(report);
          break;
        case "incident":
          content = await this.generateIncidentReport(report);
          break;
        case "executive":
          content = await this.generateExecutiveReport(report);
          break;
        default:
          content = {};
      }

      // Store content
      await this.redis.set(
        `report:${report.id}:content`,
        JSON.stringify(content),
      );

      // Generate file
      if (report.format === "json") {
        await this.generateJSONFile(report, content);
      }

      this.updateReportStatus(report.id, "completed");
    } catch (error) {
      log.error({ error, reportId: report.id }, "Report generation error");
      this.updateReportStatus(report.id, "failed");
    }
  }

  private async generateDailyReport(
    report: Report,
  ): Promise<Record<string, unknown>> {
    // Get stats from Redis
    const date = report.period_start.split("T")[0];

    const stats: DailyStats = {
      date,
      total_alerts: Math.floor(Math.random() * 500),
      critical_alerts: Math.floor(Math.random() * 20),
      resolved_alerts: Math.floor(Math.random() * 400),
      events_processed: Math.floor(Math.random() * 100000),
      avg_response_time: Math.floor(Math.random() * 300),
      top_threats: [
        { name: "Brute Force Attack", count: Math.floor(Math.random() * 50) },
        { name: "Malware Detection", count: Math.floor(Math.random() * 30) },
        { name: "Phishing Attempt", count: Math.floor(Math.random() * 25) },
        {
          name: "Suspicious Network Activity",
          count: Math.floor(Math.random() * 20),
        },
      ],
      affected_assets: ["server-01", "workstation-15", "database-01"],
    };

    return {
      summary: {
        title: `Daily Security Report - ${date}`,
        period: `${report.period_start} to ${report.period_end}`,
      },
      statistics: stats,
      recommendations: [
        "Review and block malicious IPs identified",
        "Update firewall rules for suspicious ports",
        "Conduct security awareness training",
      ],
    };
  }

  private async generateWeeklyReport(
    report: Report,
  ): Promise<Record<string, unknown>> {
    const dailyStats: DailyStats[] = [];
    const startDate = new Date(report.period_start);

    for (let i = 0; i < 7; i++) {
      const date = new Date(startDate);
      date.setDate(date.getDate() + i);

      dailyStats.push({
        date: date.toISOString().split("T")[0],
        total_alerts: Math.floor(Math.random() * 500),
        critical_alerts: Math.floor(Math.random() * 20),
        resolved_alerts: Math.floor(Math.random() * 400),
        events_processed: Math.floor(Math.random() * 100000),
        avg_response_time: Math.floor(Math.random() * 300),
        top_threats: [],
        affected_assets: [],
      });
    }

    const totalAlerts = dailyStats.reduce((sum, d) => sum + d.total_alerts, 0);
    const totalCritical = dailyStats.reduce(
      (sum, d) => sum + d.critical_alerts,
      0,
    );

    return {
      summary: {
        title: "Weekly Security Report",
        period: `${report.period_start} to ${report.period_end}`,
        total_alerts: totalAlerts,
        critical_alerts: totalCritical,
      },
      daily_breakdown: dailyStats,
      trends: {
        alert_trend: totalAlerts > 2000 ? "increasing" : "stable",
        severity_distribution: {
          critical: totalCritical,
          high: 50,
          medium: 200,
          low: 300,
        },
      },
      top_issues: [
        "Multiple failed login attempts from external IPs",
        "Unusual outbound traffic patterns",
        "Potential data exfiltration attempt",
      ],
    };
  }

  private async generateMonthlyReport(
    report: Report,
  ): Promise<Record<string, unknown>> {
    const weeklyData = await this.generateWeeklyReport(report);

    return {
      summary: {
        title: "Monthly Security Report",
        period: `${report.period_start} to ${report.period_end}`,
      },
      weekly_data: weeklyData,
      metrics: {
        mttd: "15 minutes",
        mttr: "2 hours",
        coverage: "98%",
        false_positive_rate: "12%",
      },
      compliance: {
        soc2: "compliant",
        iso27001: "compliant",
        pci_dss: "partial",
      },
      budget: {
        spent: "65%",
        remaining: "35%",
      },
    };
  }

  private async generateIncidentReport(
    report: Report,
  ): Promise<Record<string, unknown>> {
    const incidentId = (report.metadata?.incident_id as string) || "INC-001";

    const incident: IncidentReport = {
      incident_id: incidentId,
      title: "Security Incident - Unauthorized Access",
      timeline: [
        {
          timestamp: "2024-01-15T08:00:00Z",
          action: "Alert triggered",
          actor: "SIEM",
        },
        {
          timestamp: "2024-01-15T08:05:00Z",
          action: "Analyst notified",
          actor: "System",
        },
        {
          timestamp: "2024-01-15T08:15:00Z",
          action: "Investigation started",
          actor: "analyst@company.com",
        },
        {
          timestamp: "2024-01-15T08:45:00Z",
          action: "Compromised account identified",
          actor: "analyst@company.com",
        },
        {
          timestamp: "2024-01-15T09:00:00Z",
          action: "Account disabled",
          actor: "analyst@company.com",
        },
        {
          timestamp: "2024-01-15T10:00:00Z",
          action: "Incident resolved",
          actor: "analyst@company.com",
        },
      ],
      root_cause: "Weak password policy combined with lack of MFA",
      impact: "1 user account compromised, no data exfiltration detected",
      recommendations: [
        "Implement mandatory MFA for all users",
        "Review password policy requirements",
        "Enable additional logging for authentication events",
        "Schedule security awareness training",
      ],
    };

    return {
      summary: {
        title: "Incident Report",
        incident_id: incidentId,
      },
      incident,
      evidence: [
        { type: "log", location: "/logs/auth-2024-01-15.json" },
        { type: "network", location: "/network/capture-2024-01-15.pcap" },
      ],
    };
  }

  private async generateExecutiveReport(
    report: Report,
  ): Promise<Record<string, unknown>> {
    return {
      summary: {
        title: "Executive Security Summary",
        period: `${report.period_start} to ${report.period_end}`,
        prepared_for: "C-Suite",
        prepared_by: "SECURE SHIELD SOC Team",
      },
      key_metrics: {
        total_security_events: 12547,
        incidents_detected: 23,
        incidents_resolved: 21,
        average_response_time: "45 minutes",
        security_score: "85/100",
      },
      risk_assessment: {
        critical: 2,
        high: 5,
        medium: 12,
        low: 28,
      },
      trends: {
        attacks: "increasing",
        sophistication: "increasing",
        detection_rate: "95%",
      },
      recommendations: [
        "Increase SOC coverage to 24/7",
        "Invest in advanced threat detection",
        "Conduct quarterly penetration testing",
      ],
      budget_proposal: {
        description: "Q2 Security Enhancement",
        items: [
          { item: "24/7 SOC Coverage", cost: 15000 },
          { item: "Advanced SIEM", cost: 25000 },
          { item: "Security Training", cost: 5000 },
        ],
        total: 45000,
      },
    };
  }

  private async generateJSONFile(
    report: Report,
    content: Record<string, unknown>,
  ) {
    const filename = `${report.id}.json`;
    const filepath = path.join("/tmp/reports", filename);

    await fs.mkdir("/tmp/reports", { recursive: true });
    await fs.writeFile(filepath, JSON.stringify(content, null, 2));
  }

  // API Methods
  async getReport(id: string): Promise<Report | null> {
    const data = await this.redis.get(`report:${id}`);
    return data ? JSON.parse(data) : null;
  }

  async getReportContent(id: string): Promise<Record<string, unknown> | null> {
    const data = await this.redis.get(`report:${id}:content`);
    return data ? JSON.parse(data) : null;
  }

  async listReports(filters?: {
    type?: string;
    status?: string;
    limit?: number;
  }): Promise<Report[]> {
    const keys = await this.redis.keys("report:*");
    const reports: Report[] = [];

    for (const key of keys) {
      if (key.includes(":content")) continue;

      const data = await this.redis.get(key);
      if (!data) continue;

      const report: Report = JSON.parse(data);

      if (filters?.type && report.type !== filters.type) continue;
      if (filters?.status && report.status !== filters.status) continue;

      reports.push(report);
    }

    return reports
      .sort(
        (a, b) =>
          new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
      )
      .slice(0, filters?.limit || 50);
  }

  async deleteReport(id: string): Promise<boolean> {
    await this.redis.del(`report:${id}`);
    await this.redis.del(`report:${id}:content`);
    return true;
  }
}

// Fastify API
export async function buildApp(
  reports: ReportService,
): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  // Routes
  app.get("/health", async () => ({ status: "ok" }));

  // Create report
  const createReportSchema = z.object({
    type: z.enum([
      "daily",
      "weekly",
      "monthly",
      "incident",
      "compliance",
      "executive",
    ]),
    period_start: z.string(),
    period_end: z.string(),
    format: z.enum(["pdf", "html", "json"]).default("json"),
    name: z.string().optional(),
    metadata: z.record(z.unknown()).optional(),
  });

  app.post<{ Body: z.infer<typeof createReportSchema> }>(
    "/api/v1/reports",
    { schema: { body: createReportSchema } },
    async (request) => {
      return reports.createReport(
        request.body.type,
        request.body.period_start,
        request.body.period_end,
        request.body.format,
        request.body.name,
        request.body.metadata,
      );
    },
  );

  // List reports
  app.get("/api/v1/reports", async (request) => {
    const { type, status, limit } = request.query as {
      type?: string;
      status?: string;
      limit?: string;
    };
    return reports.listReports({
      type,
      status,
      limit: limit ? parseInt(limit) : undefined,
    });
  });

  // Get report
  app.get<{ Params: { id: string } }>(
    "/api/v1/reports/:id",
    async (request) => {
      const report = await reports.getReport(request.params.id);
      if (!report) {
        return { error: "Report not found" };
      }
      return report;
    },
  );

  // Get report content
  app.get<{ Params: { id: string } }>(
    "/api/v1/reports/:id/content",
    async (request) => {
      const content = await reports.getReportContent(request.params.id);
      if (!content) {
        return { error: "Report content not found" };
      }
      return content;
    },
  );

  // Download report
  app.get<{ Params: { id: string } }>(
    "/api/v1/reports/:id/download",
    async (request) => {
      const report = await reports.getReport(request.params.id);
      if (!report || report.status !== "completed") {
        return { error: "Report not available for download" };
      }

      return {
        download_url: `/api/v1/reports/${report.id}/content`,
        format: report.format,
      };
    },
  );

  // Delete report
  app.delete<{ Params: { id: string } }>(
    "/api/v1/reports/:id",
    async (request) => {
      await reports.deleteReport(request.params.id);
      return { success: true };
    },
  );

  return app;
}

// Main
async function main() {
  const reports = new ReportService();

  const app = await buildApp(reports);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`Reports API listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
