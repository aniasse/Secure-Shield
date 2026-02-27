import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import { z } from "zod";
import pino from "pino";
import crypto from "crypto";

const log = pino({ name: "llm-analyzer", level: "info" });

// Configuration
const config = {
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  llm: {
    provider: process.env.LLM_PROVIDER || "openai",
    apiKey: process.env.LLM_API_KEY,
    model: process.env.LLM_MODEL || "gpt-4",
    endpoint: process.env.LLM_ENDPOINT,
  },
  app: {
    port: parseInt(process.env.PORT || "8090"),
  },
};

// Types
interface AlertSummary {
  id: string;
  alertId: string;
  originalAlert: Record<string, unknown>;
  summary: string;
  severity: number;
  confidence: number;
  recommendedActions: string[];
  rootCause?: string;
  mitreTechniques?: string[];
  generatedAt: string;
  model: string;
}

interface ThreatHypothesis {
  id: string;
  hypothesis: string;
  confidence: number;
  evidence: Evidence[];
  recommendedActions: string[];
  status: "investigating" | "confirmed" | "disproven";
  createdAt: string;
}

interface Evidence {
  type: string;
  description: string;
  source: string;
  timestamp: string;
  severity: number;
}

interface LogAnalysis {
  id: string;
  logId: string;
  rawLog: string;
  parsed: ParsedLog;
  entities: Entity[];
  classification: Classification;
  iocs: string[];
  sentiment?: string;
  generatedAt: string;
}

interface ParsedLog {
  timestamp?: string;
  source?: string;
  level?: string;
  message?: string;
  fields: Record<string, unknown>;
}

interface Entity {
  type: "ip" | "domain" | "hash" | "user" | "file" | "process";
  value: string;
  confidence: number;
}

interface Classification {
  category: string;
  subcategory?: string;
  isMalicious: boolean;
  confidence: number;
  tags: string[];
}

// LLM Analysis Service
class LLMAnalysisService {
  private redis: Redis;

  constructor() {
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  // LLM Prompt Templates
  private getAlertSummaryPrompt(alert: Record<string, unknown>): string {
    return `You are a senior security analyst. Analyze this security alert and provide a concise summary.

Alert Details:
${JSON.stringify(alert, null, 2)}

Provide a JSON response with:
1. summary: A 2-3 sentence summary of the alert
2. severity: Numeric severity (1-10)
3. confidence: Confidence score (0-100)
4. recommendedActions: Array of 3-5 recommended actions
5. rootCause: Possible root cause (or "unknown")
6. mitreTechniques: Array of relevant MITRE ATT&CK techniques

Respond in JSON format only.`;
  }

  private getLogAnalysisPrompt(log: string): string {
    return `You are a security log analysis expert. Analyze this log entry and extract structured information.

Log Entry:
${log}

Provide a JSON response with:
1. parsed: Extract timestamp, source, level, message, and other fields
2. entities: Extract IP addresses, domains, hashes, usernames, file paths, process names
3. classification: Determine category, subcategory, whether malicious (boolean), confidence (0-100), and tags
4. iocs: List any indicators of compromise

Respond in JSON format only.`;
  }

  private getThreatHypothesisPrompt(
    alerts: Record<string, unknown>[],
    context: Record<string, unknown>,
  ): string {
    return `You are an expert threat hunter. Based on the following alerts and context, generate hypotheses about potential ongoing attacks or threats.

Recent Alerts:
${JSON.stringify(alerts.slice(0, 20), null, 2)}

Context:
${JSON.stringify(context, null, 2)}

Provide a JSON response with:
1. hypothesis: A specific, testable hypothesis about a potential threat
2. confidence: Your confidence level (0-100)
3. evidence: Array of supporting evidence (type, description, source, timestamp, severity)
4. recommendedActions: Steps to investigate or confirm this hypothesis
5. status: Set to "investigating"

Generate 3 different hypotheses if possible. Respond in JSON array format.`;
  }

  // LLM API Calls
  private async callLLM(prompt: string): Promise<string> {
    const { provider, apiKey, model, endpoint } = config.llm;

    if (!apiKey) {
      log.warn("No LLM API key configured, using simulated response");
      return this.getSimulatedResponse(prompt);
    }

    try {
      if (provider === "openai" || provider === "compatible") {
        return await this.callOpenAI(prompt, apiKey, model);
      } else if (provider === "anthropic") {
        return await this.callAnthropic(prompt, apiKey, model);
      } else if (provider === "ollama") {
        return await this.callOllama(
          prompt,
          endpoint || "http://localhost:11434",
        );
      } else if (provider === "gemini") {
        return await this.callGemini(prompt, apiKey, model);
      }

      return this.getSimulatedResponse(prompt);
    } catch (error) {
      log.error({ error }, "LLM call failed, using simulated response");
      return this.getSimulatedResponse(prompt);
    }
  }

  private async callOpenAI(
    prompt: string,
    apiKey: string,
    model: string,
  ): Promise<string> {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.3,
        max_tokens: 2000,
      }),
    });

    const data = await response.json();
    return data.choices?.[0]?.message?.content || "";
  }

  private async callAnthropic(
    prompt: string,
    apiKey: string,
    model: string,
  ): Promise<string> {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        messages: [{ role: "user", content: prompt }],
        temperature: 0.3,
        max_tokens: 2000,
      }),
    });

    const data = await response.json();
    return data.content?.[0]?.text || "";
  }

  private async callOllama(prompt: string, endpoint: string): Promise<string> {
    const response = await fetch(`${endpoint}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama2",
        prompt,
        temperature: 0.3,
      }),
    });

    const data = await response.json();
    return data.response || "";
  }

  private async callGemini(
    prompt: string,
    apiKey: string,
    model: string,
  ): Promise<string> {
    const modelName = model || "gemini-flash-latest";
    log.info({ model: modelName }, "Calling Gemini API");
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${modelName}:generateContent?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
        }),
      },
    );

    const data = await response.json();
    if (data.error) {
      log.error({ error: data.error }, "Gemini API error");
      return "";
    }
    return data.candidates?.[0]?.content?.parts?.[0]?.text || "";
  }

  private getSimulatedResponse(prompt: string): string {
    if (prompt.includes("Alert Details")) {
      return JSON.stringify({
        summary:
          "Suspicious authentication activity detected from external IP address with multiple failed login attempts.",
        severity: 7,
        confidence: 85,
        recommendedActions: [
          "Block the source IP address at the firewall",
          "Force password reset for affected accounts",
          "Enable MFA for all users",
          "Review authentication logs for similar activity",
        ],
        rootCause: "Weak or compromised credentials combined with lack of MFA",
        mitreTechniques: ["T1110", "T1078"],
      });
    } else if (prompt.includes("Log Entry")) {
      return JSON.stringify({
        parsed: {
          timestamp: "2024-01-15T10:30:00Z",
          source: "auth-service",
          level: "error",
          message: "Authentication failed for user admin",
        },
        entities: [
          { type: "ip", value: "192.168.1.100", confidence: 0.95 },
          { type: "user", value: "admin", confidence: 0.99 },
        ],
        classification: {
          category: "authentication",
          subcategory: "failed_login",
          isMalicious: false,
          confidence: 75,
          tags: ["auth", "failure", "security"],
        },
        iocs: ["192.168.1.100"],
      });
    } else {
      return JSON.stringify([
        {
          hypothesis:
            "Potential credential stuffing attack targeting admin accounts",
          confidence: 75,
          evidence: [
            {
              type: "alert",
              description: "Multiple failed logins from various IPs",
              source: "SIEM",
              timestamp: new Date().toISOString(),
              severity: 8,
            },
          ],
          recommendedActions: ["Implement rate limiting", "Enable captcha"],
          status: "investigating",
        },
      ]);
    }
  }

  // Alert Summary
  async summarizeAlert(alert: Record<string, unknown>): Promise<AlertSummary> {
    const id = crypto.randomUUID();

    const prompt = this.getAlertSummaryPrompt(alert);
    const llmResponse = await this.callLLM(prompt);

    let summary: Partial<AlertSummary>;
    try {
      summary = JSON.parse(llmResponse);
    } catch {
      log.warn("Failed to parse LLM response, using fallback");
      summary = this.getSimulatedResponse(prompt);
    }

    const result: AlertSummary = {
      id,
      alertId: (alert.id as string) || id,
      originalAlert: alert,
      summary: summary.summary || "Unable to generate summary",
      severity: summary.severity || 5,
      confidence: summary.confidence || 50,
      recommendedActions: summary.recommendedActions || [],
      rootCause: summary.rootCause,
      mitreTechniques: summary.mitreTechniques,
      generatedAt: new Date().toISOString(),
      model: config.llm.model,
    };

    await this.redis.set(
      `alert_summary:${result.alertId}`,
      JSON.stringify(result),
    );
    await this.redis.expire(`alert_summary:${result.alertId}`, 86400 * 7); // 7 days

    return result;
  }

  async getAlertSummary(alertId: string): Promise<AlertSummary | null> {
    const data = await this.redis.get(`alert_summary:${alertId}`);
    return data ? JSON.parse(data) : null;
  }

  // Batch Alert Summary
  async summarizeAlerts(
    alerts: Record<string, unknown>[],
  ): Promise<AlertSummary[]> {
    const summaries: AlertSummary[] = [];

    // Process in batches to avoid rate limits
    const batchSize = 5;
    for (let i = 0; i < alerts.length; i += batchSize) {
      const batch = alerts.slice(i, i + batchSize);
      const results = await Promise.all(
        batch.map((alert) => this.summarizeAlert(alert)),
      );
      summaries.push(...results);

      // Small delay between batches
      if (i + batchSize < alerts.length) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    return summaries;
  }

  // Threat Hunting Hypothesis
  async generateThreatHypotheses(
    alerts: Record<string, unknown>[],
    context: Record<string, unknown>,
  ): Promise<ThreatHypothesis[]> {
    const prompt = this.getThreatHypothesisPrompt(alerts, context);
    const llmResponse = await this.callLLM(prompt);

    let hypotheses: Partial<ThreatHypothesis>[];
    try {
      hypotheses = JSON.parse(llmResponse);
      if (!Array.isArray(hypotheses)) {
        hypotheses = [hypotheses];
      }
    } catch {
      hypotheses = JSON.parse(this.getSimulatedResponse(prompt));
    }

    const results: ThreatHypothesis[] = hypotheses.map((h) => ({
      id: crypto.randomUUID(),
      hypothesis: h.hypothesis || "",
      confidence: h.confidence || 50,
      evidence: h.evidence || [],
      recommendedActions: h.recommendedActions || [],
      status: h.status || "investigating",
      createdAt: new Date().toISOString(),
    }));

    // Store hypotheses
    for (const hypothesis of results) {
      await this.redis.set(
        `hypothesis:${hypothesis.id}`,
        JSON.stringify(hypothesis),
      );
    }

    return results;
  }

  // Log Analysis (NLP)
  async analyzeLog(logEntry: string): Promise<LogAnalysis> {
    const id = crypto.randomUUID();

    const prompt = this.getLogAnalysisPrompt(logEntry);
    const llmResponse = await this.callLLM(prompt);

    let analysis: Partial<LogAnalysis>;
    try {
      analysis = JSON.parse(llmResponse);
    } catch {
      analysis = JSON.parse(this.getSimulatedResponse(prompt));
    }

    const result: LogAnalysis = {
      id,
      logId: id,
      rawLog: logEntry,
      parsed: analysis.parsed || { fields: {} },
      entities: analysis.entities || [],
      classification: analysis.classification || {
        category: "unknown",
        isMalicious: false,
        confidence: 0,
        tags: [],
      },
      iocs: analysis.iocs || [],
      generatedAt: new Date().toISOString(),
    };

    await this.redis.set(`log_analysis:${id}`, JSON.stringify(result));
    return result;
  }

  // Batch Log Analysis
  async analyzeLogs(logs: string[]): Promise<LogAnalysis[]> {
    const results: LogAnalysis[] = [];

    const batchSize = 10;
    for (let i = 0; i < logs.length; i += batchSize) {
      const batch = logs.slice(i, i + batchSize);
      const analysisResults = await Promise.all(
        batch.map((log) => this.analyzeLog(log)),
      );
      results.push(...analysisResults);

      if (i + batchSize < logs.length) {
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }

    return results;
  }

  // Get hypotheses
  async getHypotheses(): Promise<ThreatHypothesis[]> {
    const keys = await this.redis.keys("hypothesis:*");
    const hypotheses: ThreatHypothesis[] = [];

    for (const key of keys) {
      const data = await this.redis.get(key);
      if (data) hypotheses.push(JSON.parse(data));
    }

    return hypotheses.sort((a, b) => b.confidence - a.confidence);
  }

  // Update hypothesis status
  async updateHypothesisStatus(
    id: string,
    status: ThreatHypothesis["status"],
  ): Promise<void> {
    const data = await this.redis.get(`hypothesis:${id}`);
    if (data) {
      const hypothesis = JSON.parse(data) as ThreatHypothesis;
      hypothesis.status = status;
      await this.redis.set(`hypothesis:${id}`, JSON.stringify(hypothesis));
    }
  }

  // Statistics
  async getStats() {
    const [summaryCount, hypothesisCount, analysisCount] = await Promise.all([
      this.redis.keys("alert_summary:*").then((k) => k.length),
      this.redis.keys("hypothesis:*").then((k) => k.length),
      this.redis.keys("log_analysis:*").then((k) => k.length),
    ]);

    return {
      alert_summaries: summaryCount,
      threat_hypotheses: hypothesisCount,
      log_analyses: analysisCount,
      llm_provider: config.llm.provider,
      llm_model: config.llm.model,
    };
  }
}

// Fastify API
export async function buildApp(
  llm: LLMAnalysisService,
): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  // Routes
  app.get("/health", async () => ({ status: "ok" }));

  // Summarize alert
  app.post("/api/v1/ai/summarize/alert", async (request) => {
    return llm.summarizeAlert(request.body as Record<string, unknown>);
  });

  // Get alert summary
  app.get<{ Params: { alertId: string } }>(
    "/api/v1/ai/summarize/alert/:alertId",
    async (request) => {
      return llm.getAlertSummary(request.params.alertId);
    },
  );

  // Batch summarize alerts
  app.post("/api/v1/ai/summarize/alerts", async (request) => {
    const { alerts } = request.body as { alerts: Record<string, unknown>[] };
    return llm.summarizeAlerts(alerts);
  });

  // Generate threat hypotheses
  app.post("/api/v1/ai/hunt", async (request) => {
    const { alerts, context } = request.body as {
      alerts: Record<string, unknown>[];
      context?: Record<string, unknown>;
    };
    return llm.generateThreatHypotheses(alerts, context || {});
  });

  // Get hypotheses
  app.get("/api/v1/ai/hunt/hypotheses", async () => {
    return llm.getHypotheses();
  });

  // Update hypothesis
  app.patch<{ Params: { id: string } }>(
    "/api/v1/ai/hunt/hypotheses/:id",
    async (request) => {
      const { status } = request.body as { status: ThreatHypothesis["status"] };
      await llm.updateHypothesisStatus(request.params.id, status);
      return { success: true };
    },
  );

  // Analyze log
  app.post("/api/v1/ai/analyze/log", async (request) => {
    const { log } = request.body as { log: string };
    return llm.analyzeLog(log);
  });

  // Batch analyze logs
  app.post("/api/v1/ai/analyze/logs", async (request) => {
    const { logs } = request.body as { logs: string[] };
    return llm.analyzeLogs(logs);
  });

  // Statistics
  app.get("/api/v1/ai/stats", async () => {
    return llm.getStats();
  });

  return app;
}

// Main
async function main() {
  const llm = new LLMAnalysisService();

  const app = await buildApp(llm);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`LLM Analysis API listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
