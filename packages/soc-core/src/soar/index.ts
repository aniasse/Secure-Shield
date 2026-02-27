import { Kafka, EachMessagePayload } from "kafkajs";
import Redis from "ioredis";
import { FastifyInstance } from "fastify";
import { z } from "zod";
import pino from "pino";
import crypto from "crypto";

const log = pino({ name: "soar", level: "info" });

// Configuration
const config = {
  kafka: {
    brokers: [process.env.KAFKA_BROKER || "localhost:9092"],
    clientId: "soc-soar",
  },
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
  app: {
    port: parseInt(process.env.PORT || "8082"),
  },
};

// Types
interface Playbook {
  id: string;
  name: string;
  description: string;
  trigger: {
    type: "alert_type" | "severity" | "manual";
    condition: Record<string, unknown>;
  };
  steps: PlaybookStep[];
  enabled: boolean;
  version: number;
}

interface PlaybookStep {
  id: string;
  name: string;
  action: {
    type: string;
    target: string;
    operation: string;
    parameters: Record<string, unknown>;
  };
  condition?: string;
  timeout: number;
  retry: {
    count: number;
    delay: number;
  };
  onFailure: "continue" | "stop" | "rollback";
}

interface Execution {
  id: string;
  playbookId: string;
  status: "running" | "completed" | "failed";
  triggerData: Record<string, unknown>;
  currentStep?: string;
  stepResults: StepResult[];
  startedAt: string;
  completedAt?: string;
  error?: string;
}

interface StepResult {
  stepId: string;
  status: "success" | "failure" | "skipped";
  output?: Record<string, unknown>;
  duration: number;
  error?: string;
}

interface Integration {
  name: string;
  execute(
    operation: string,
    params: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
}

// Integrations Registry
const integrations: Record<string, Integration> = {
  firewall: {
    name: "firewall",
    async execute(operation: string, params: Record<string, unknown>) {
      switch (operation) {
        case "block_ip":
          log.info({ params }, "Blocking IP on firewall");
          return { success: true, action: "blocked", ip: params.ip };
        case "unblock_ip":
          log.info({ params }, "Unblocking IP on firewall");
          return { success: true, action: "unblocked", ip: params.ip };
        default:
          throw new Error(`Unknown operation: ${operation}`);
      }
    },
  },
  edr: {
    name: "edr",
    async execute(operation: string, params: Record<string, unknown>) {
      switch (operation) {
        case "isolate_host":
          log.info({ params }, "Isolating host");
          return {
            success: true,
            action: "isolated",
            hostname: params.hostname,
          };
        case "kill_process":
          log.info({ params }, "Killing process");
          return { success: true, action: "killed", pid: params.pid };
        default:
          throw new Error(`Unknown operation: ${operation}`);
      }
    },
  },
  email: {
    name: "email",
    async execute(operation: string, params: Record<string, unknown>) {
      switch (operation) {
        case "send_alert":
          log.info({ params }, "Sending email alert");
          return { success: true, message_id: crypto.randomUUID() };
        default:
          throw new Error(`Unknown operation: ${operation}`);
      }
    },
  },
  slack: {
    name: "slack",
    async execute(operation: string, params: Record<string, unknown>) {
      switch (operation) {
        case "notify":
          log.info({ params }, "Sending Slack notification");
          return { success: true, ts: Date.now().toString() };
        default:
          throw new Error(`Unknown operation: ${operation}`);
      }
    },
  },
  ticketing: {
    name: "ticketing",
    async execute(operation: string, params: Record<string, unknown>) {
      switch (operation) {
        case "create_ticket":
          log.info({ params }, "Creating ticket");
          return { success: true, ticket_id: crypto.randomUUID() };
        case "update_ticket":
          log.info({ params }, "Updating ticket");
          return { success: true };
        default:
          throw new Error(`Unknown operation: ${operation}`);
      }
    },
  },
};

// SOAR Engine
class SOAREngine {
  private kafka: Kafka;
  private redis: Redis;
  private playbooks: Map<string, Playbook> = new Map();

  constructor() {
    this.kafka = new Kafka({
      clientId: config.kafka.clientId,
      brokers: config.kafka.brokers,
    });

    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  async start() {
    await this.loadPlaybooks();
    await this.startAlertConsumer();
    log.info("SOAR engine started");
  }

  private async loadPlaybooks() {
    const keys = await this.redis.keys("playbook:*");
    for (const key of keys) {
      const data = await this.redis.get(key);
      if (data) {
        const playbook: Playbook = JSON.parse(data);
        this.playbooks.set(playbook.id, playbook);
      }
    }
    log.info({ count: this.playbooks.size }, "Playbooks loaded");
  }

  private async startAlertConsumer() {
    const consumer = this.kafka.consumer({ groupId: "soar-engine" });

    await consumer.connect();
    await consumer.subscribe({ topic: "alerts", fromBeginning: false });

    await consumer.run({
      eachMessage: async (payload: EachMessagePayload) => {
        await this.processAlert(payload);
      },
    });
  }

  private async processAlert(payload: EachMessagePayload) {
    try {
      const alert = JSON.parse(payload.message.value?.toString() || "{}");

      for (const [id, playbook] of this.playbooks) {
        if (!playbook.enabled) continue;

        if (this.matchesTrigger(playbook.trigger, alert)) {
          await this.executePlaybook(playbook, alert);
        }
      }
    } catch (error) {
      log.error({ error }, "Failed to process alert");
    }
  }

  private matchesTrigger(
    trigger: Playbook["trigger"],
    alert: Record<string, unknown>,
  ): boolean {
    switch (trigger.type) {
      case "alert_type":
        return alert.title?.includes(trigger.condition.type as string);
      case "severity":
        return (
          (alert.severity as number) >=
          (trigger.condition.min_severity as number)
        );
      case "manual":
        return false;
      default:
        return false;
    }
  }

  async executePlaybook(
    playbook: Playbook,
    triggerData: Record<string, unknown>,
  ): Promise<Execution> {
    const execution: Execution = {
      id: crypto.randomUUID(),
      playbookId: playbook.id,
      status: "running",
      triggerData,
      stepResults: [],
      startedAt: new Date().toISOString(),
    };

    // Store execution
    await this.redis.set(
      `execution:${execution.id}`,
      JSON.stringify(execution),
    );

    log.info(
      { playbook: playbook.name, execution: execution.id },
      "Starting playbook execution",
    );

    for (const step of playbook.steps) {
      execution.currentStep = step.id;

      const result = await this.executeStep(
        step,
        triggerData,
        execution.stepResults,
      );
      execution.stepResults.push(result);

      // Update execution state
      await this.redis.set(
        `execution:${execution.id}`,
        JSON.stringify(execution),
      );

      if (result.status === "failure" && step.onFailure === "stop") {
        execution.status = "failed";
        execution.error = result.error;
        break;
      }

      // Add step output to trigger data for next steps
      if (result.output) {
        for (const [key, value] of Object.entries(result.output)) {
          triggerData[`${step.id}.${key}`] = value;
        }
      }
    }

    if (execution.status === "running") {
      execution.status = "completed";
    }

    execution.completedAt = new Date().toISOString();
    await this.redis.set(
      `execution:${execution.id}`,
      JSON.stringify(execution),
    );

    log.info(
      {
        playbook: playbook.name,
        execution: execution.id,
        status: execution.status,
      },
      "Playbook execution completed",
    );

    return execution;
  }

  private async executeStep(
    step: PlaybookStep,
    data: Record<string, unknown>,
    previousResults: StepResult[],
  ): Promise<StepResult> {
    const start = Date.now();

    // Evaluate condition if present
    if (step.condition) {
      const conditionMet = this.evaluateCondition(
        step.condition,
        data,
        previousResults,
      );
      if (!conditionMet) {
        return {
          stepId: step.id,
          status: "skipped",
          duration: Date.now() - start,
        };
      }
    }

    // Get integration
    const integration = integrations[step.action.target];
    if (!integration) {
      return {
        stepId: step.id,
        status: "failure",
        error: `Integration ${step.action.target} not found`,
        duration: Date.now() - start,
      };
    }

    // Interpolate parameters
    const params = this.interpolateParameters(step.action.parameters, data);

    // Execute with retry
    let lastError: Error | undefined;
    for (let i = 0; i <= step.retry.count; i++) {
      try {
        const output = await Promise.race([
          integration.execute(step.action.operation, params),
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Timeout")), step.timeout * 1000),
          ),
        ]);

        return {
          stepId: step.id,
          status: "success",
          output: output as Record<string, unknown>,
          duration: Date.now() - start,
        };
      } catch (error) {
        lastError = error as Error;

        if (i < step.retry.count) {
          await new Promise((resolve) =>
            setTimeout(resolve, step.retry.delay * 1000),
          );
        }
      }
    }

    return {
      stepId: step.id,
      status: "failure",
      error: lastError?.message,
      duration: Date.now() - start,
    };
  }

  private evaluateCondition(
    condition: string,
    data: Record<string, unknown>,
    _previousResults: StepResult[],
  ): boolean {
    // Simple condition evaluation
    // In production, use a proper expression parser
    try {
      const [field, operator, value] = condition.split(" ");
      const actualValue = this.getNestedValue(data, field);

      switch (operator) {
        case "==":
          return actualValue == value;
        case "!=":
          return actualValue != value;
        case ">":
          return Number(actualValue) > Number(value);
        case "<":
          return Number(actualValue) < Number(value);
        case "contains":
          return String(actualValue).includes(value);
        default:
          return true;
      }
    } catch {
      return false;
    }
  }

  private getNestedValue(obj: Record<string, unknown>, path: string): unknown {
    return path.split(".").reduce((acc: unknown, part) => {
      if (acc && typeof acc === "object") {
        return (acc as Record<string, unknown>)[part];
      }
      return undefined;
    }, obj);
  }

  private interpolateParameters(
    params: Record<string, unknown>,
    data: Record<string, unknown>,
  ): Record<string, unknown> {
    const result: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(params)) {
      if (
        typeof value === "string" &&
        value.startsWith("${") &&
        value.endsWith("}")
      ) {
        const path = value.slice(2, -1);
        result[key] = this.getNestedValue(data, path) ?? value;
      } else {
        result[key] = value;
      }
    }

    return result;
  }

  // API Methods
  async getPlaybooks(): Promise<Playbook[]> {
    return Array.from(this.playbooks.values());
  }

  async getPlaybook(id: string): Promise<Playbook | null> {
    return this.playbooks.get(id) || null;
  }

  async createPlaybook(playbook: Omit<Playbook, "id">): Promise<Playbook> {
    const id = crypto.randomUUID();
    const fullPlaybook: Playbook = { id, ...playbook };

    this.playbooks.set(id, fullPlaybook);
    await this.redis.set(`playbook:${id}`, JSON.stringify(fullPlaybook));

    return fullPlaybook;
  }

  async updatePlaybook(
    id: string,
    updates: Partial<Playbook>,
  ): Promise<Playbook | null> {
    const existing = this.playbooks.get(id);
    if (!existing) return null;

    const updated: Playbook = {
      ...existing,
      ...updates,
      version: existing.version + 1,
    };
    this.playbooks.set(id, updated);
    await this.redis.set(`playbook:${id}`, JSON.stringify(updated));

    return updated;
  }

  async deletePlaybook(id: string): Promise<boolean> {
    this.playbooks.delete(id);
    return (await this.redis.del(`playbook:${id}`)) > 0;
  }

  async getExecution(id: string): Promise<Execution | null> {
    const data = await this.redis.get(`execution:${id}`);
    return data ? JSON.parse(data) : null;
  }

  async getExecutions(filters?: {
    playbookId?: string;
    status?: string;
  }): Promise<Execution[]> {
    const keys = await this.redis.keys("execution:*");
    const executions: Execution[] = [];

    for (const key of keys) {
      const data = await this.redis.get(key);
      if (data) {
        const exec = JSON.parse(data) as Execution;
        if (filters?.playbookId && exec.playbookId !== filters.playbookId)
          continue;
        if (filters?.status && exec.status !== filters.status) continue;
        executions.push(exec);
      }
    }

    return executions.sort((a, b) => b.startedAt.localeCompare(a.startedAt));
  }

  async runPlaybookManually(
    playbookId: string,
    triggerData: Record<string, unknown>,
  ): Promise<Execution> {
    const playbook = this.playbooks.get(playbookId);
    if (!playbook) {
      throw new Error(`Playbook ${playbookId} not found`);
    }

    return this.executePlaybook(playbook, triggerData);
  }
}

// Fastify API
export async function buildApp(soar: SOAREngine): Promise<FastifyInstance> {
  const { default: fastify } = await import("fastify");
  const app = fastify();

  // Routes
  app.get("/health", async () => ({ status: "ok" }));

  // Playbooks
  app.get("/api/v1/soar/playbooks", async () => {
    return soar.getPlaybooks();
  });

  app.get<{ Params: { id: string } }>(
    "/api/v1/soar/playbooks/:id",
    async (request) => {
      return soar.getPlaybook(request.params.id);
    },
  );

  const playbookSchema = z.object({
    name: z.string(),
    description: z.string(),
    trigger: z.object({
      type: z.enum(["alert_type", "severity", "manual"]),
      condition: z.record(z.unknown()),
    }),
    steps: z.array(
      z.object({
        id: z.string(),
        name: z.string(),
        action: z.object({
          type: z.string(),
          target: z.string(),
          operation: z.string(),
          parameters: z.record(z.unknown()),
        }),
        condition: z.string().optional(),
        timeout: z.number().default(30),
        retry: z
          .object({
            count: z.number().default(0),
            delay: z.number().default(5),
          })
          .default({ count: 0, delay: 5 }),
        onFailure: z.enum(["continue", "stop", "rollback"]).default("continue"),
      }),
    ),
    enabled: z.boolean().default(true),
  });

  app.post<{ Body: z.infer<typeof playbookSchema> }>(
    "/api/v1/soar/playbooks",
    { schema: { body: playbookSchema } },
    async (request) => {
      return soar.createPlaybook(request.body);
    },
  );

  app.patch<{
    Params: { id: string };
    Body: Partial<z.infer<typeof playbookSchema>>;
  }>("/api/v1/soar/playbooks/:id", async (request) => {
    return soar.updatePlaybook(request.params.id, request.body);
  });

  app.delete<{ Params: { id: string } }>(
    "/api/v1/soar/playbooks/:id",
    async (request) => {
      return { success: await soar.deletePlaybook(request.params.id) };
    },
  );

  // Executions
  app.get("/api/v1/soar/executions", async (request) => {
    const { playbook_id, status } = request.query as {
      playbook_id?: string;
      status?: string;
    };
    return soar.getExecutions({ playbookId: playbook_id, status });
  });

  app.get<{ Params: { id: string } }>(
    "/api/v1/soar/executions/:id",
    async (request) => {
      return soar.getExecution(request.params.id);
    },
  );

  app.post<{ Params: { id: string }; Body: Record<string, unknown> }>(
    "/api/v1/soar/playbooks/:id/run",
    async (request) => {
      return soar.runPlaybookManually(request.params.id, request.body);
    },
  );

  // Integrations
  app.get("/api/v1/soar/integrations", async () => {
    return Object.keys(integrations).map((name) => ({
      name,
      supported_operations: getSupportedOperations(name),
    }));
  });

  return app;
}

function getSupportedOperations(integration: string): string[] {
  const ops: Record<string, string[]> = {
    firewall: ["block_ip", "unblock_ip"],
    edr: ["isolate_host", "kill_process"],
    email: ["send_alert"],
    slack: ["notify"],
    ticketing: ["create_ticket", "update_ticket"],
  };
  return ops[integration] || [];
}

// Main
async function main() {
  const soar = new SOAREngine();

  // Create demo playbook
  await soar.createPlaybook({
    name: "Phishing Response",
    description: "Automated response to phishing alerts",
    trigger: {
      type: "alert_type",
      condition: { type: "phishing" },
    },
    steps: [
      {
        id: "extract_iocs",
        name: "Extract IOCs",
        action: {
          type: "transform",
          target: "internal",
          operation: "extract",
          parameters: { field: "iocs" },
        },
      },
      {
        id: "block_sender",
        name: "Block Sender",
        action: {
          type: "block",
          target: "firewall",
          operation: "block_ip",
          parameters: { ip: "${iocs.ip}" },
        },
      },
      {
        id: "notify_soc",
        name: "Notify SOC",
        action: {
          type: "notify",
          target: "slack",
          operation: "notify",
          parameters: { message: "Phishing alert: ${alert.title}" },
        },
      },
      {
        id: "create_ticket",
        name: "Create Ticket",
        action: {
          type: "ticket",
          target: "ticketing",
          operation: "create_ticket",
          parameters: {
            title: "Phishing - ${alert.title}",
            priority: "high",
          },
        },
      },
    ],
    enabled: true,
    version: 1,
  });

  await soar.start();

  const app = await buildApp(soar);
  await app.listen({ port: config.app.port, host: "0.0.0.0" });

  log.info(`SOAR API listening on port ${config.app.port}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
