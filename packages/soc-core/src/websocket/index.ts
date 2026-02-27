import { WebSocketServer, WebSocket } from "ws";
import Redis from "ioredis";
import pino from "pino";

const log = pino({ name: "websocket-server", level: "info" });

// Configuration
const config = {
  port: parseInt(process.env.WS_PORT || "8087"),
  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT || "6379"),
  },
};

// Types
interface Client {
  id: string;
  ws: WebSocket;
  subscriptions: Set<string>;
  userId?: string;
  metadata?: Record<string, unknown>;
}

interface WSMessage {
  type: string;
  payload: Record<string, unknown>;
  timestamp: string;
}

interface AlertNotification {
  alertId: string;
  severity: number;
  title: string;
  source: string;
  status: string;
}

interface MetricUpdate {
  metric: string;
  value: number;
  unit?: string;
  timestamp: string;
}

// WebSocket Server
class NotificationServer {
  private wss: WebSocketServer;
  private clients: Map<string, Client> = new Map();
  private redis: Redis;
  private redisSub: Redis;

  constructor(port: number) {
    this.wss = new WebSocketServer({ port });
    this.redis = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
    this.redisSub = new Redis({
      host: config.redis.host,
      port: config.redis.port,
    });
  }

  async start() {
    log.info({ port: config.port }, "WebSocket server starting");

    // Subscribe to notification channels
    await this.redisSub.subscribe("notifications:alerts");
    await this.redisSub.subscribe("notifications:metrics");
    await this.redisSub.subscribe("notifications:system");

    // Handle Redis messages
    this.redisSub.on("message", (channel, message) => {
      this.handleRedisMessage(channel, message);
    });

    // Handle WebSocket connections
    this.wss.on("connection", (ws, req) => {
      this.handleConnection(ws, req);
    });

    log.info("WebSocket server started");
  }

  private handleConnection(ws: WebSocket, req: any) {
    const clientId = this.generateClientId();
    const client: Client = {
      id: clientId,
      ws,
      subscriptions: new Set(),
    };

    this.clients.set(clientId, client);
    log.info({ clientId }, "Client connected");

    // Send welcome message
    this.sendToClient(clientId, {
      type: "connected",
      payload: { clientId, message: "Connected to AFRI SECURE SHIELD" },
      timestamp: new Date().toISOString(),
    });

    // Handle messages from client
    ws.on("message", (data) => {
      try {
        const message = JSON.parse(data.toString());
        this.handleClientMessage(clientId, message);
      } catch (error) {
        log.error({ error }, "Failed to parse message");
      }
    });

    // Handle disconnection
    ws.on("close", () => {
      this.clients.delete(clientId);
      log.info({ clientId }, "Client disconnected");
    });

    // Handle errors
    ws.on("error", (error) => {
      log.error({ error, clientId }, "WebSocket error");
    });
  }

  private handleClientMessage(clientId: string, message: WSMessage) {
    const client = this.clients.get(clientId);
    if (!client) return;

    switch (message.type) {
      case "subscribe":
        this.handleSubscribe(client, message.payload);
        break;
      case "unsubscribe":
        this.handleUnsubscribe(client, message.payload);
        break;
      case "auth":
        this.handleAuth(client, message.payload);
        break;
      case "ping":
        this.sendToClient(clientId, {
          type: "pong",
          payload: {},
          timestamp: new Date().toISOString(),
        });
        break;
      default:
        log.warn({ type: message.type }, "Unknown message type");
    }
  }

  private handleSubscribe(client: Client, payload: Record<string, unknown>) {
    const channel = payload.channel as string;
    if (channel) {
      client.subscriptions.add(channel);
      log.info({ clientId: client.id, channel }, "Client subscribed");

      this.sendToClient(client.id, {
        type: "subscribed",
        payload: { channel },
        timestamp: new Date().toISOString(),
      });
    }
  }

  private handleUnsubscribe(client: Client, payload: Record<string, unknown>) {
    const channel = payload.channel as string;
    if (channel) {
      client.subscriptions.delete(channel);
      log.info({ clientId: client.id, channel }, "Client unsubscribed");
    }
  }

  private handleAuth(client: Client, payload: Record<string, unknown>) {
    client.userId = payload.userId as string;
    client.metadata = payload.metadata as Record<string, unknown>;

    this.sendToClient(client.id, {
      type: "authenticated",
      payload: { userId: client.userId },
      timestamp: new Date().toISOString(),
    });
  }

  private handleRedisMessage(channel: string, message: string) {
    try {
      const data = JSON.parse(message);
      const eventType = channel.split(":")[1]; // alerts, metrics, system

      switch (eventType) {
        case "alerts":
          this.broadcastToSubscribers("alerts", data);
          break;
        case "metrics":
          this.broadcastToSubscribers("metrics", data);
          break;
        case "system":
          this.broadcastToSubscribers("system", data);
          break;
      }
    } catch (error) {
      log.error({ error, channel }, "Failed to process Redis message");
    }
  }

  private broadcastToSubscribers(channel: string, data: unknown) {
    const message = JSON.stringify({
      type: channel,
      payload: data,
      timestamp: new Date().toISOString(),
    });

    for (const [_, client] of this.clients) {
      if (client.subscriptions.has(channel) || client.subscriptions.has("*")) {
        this.sendRaw(client.ws, message);
      }
    }
  }

  sendToClient(clientId: string, message: WSMessage) {
    const client = this.clients.get(clientId);
    if (client && client.ws.readyState === WebSocket.OPEN) {
      client.ws.send(JSON.stringify(message));
    }
  }

  private sendRaw(ws: WebSocket, message: string) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  }

  private generateClientId(): string {
    return `client_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
  }

  // API Methods for external services
  async publishAlert(alert: AlertNotification) {
    await this.redis.publish("notifications:alerts", JSON.stringify(alert));
  }

  async publishMetric(metric: MetricUpdate) {
    await this.redis.publish("notifications:metrics", JSON.stringify(metric));
  }

  async publishSystemEvent(event: Record<string, unknown>) {
    await this.redis.publish("notifications:system", JSON.stringify(event));
  }

  getConnectedClients() {
    return Array.from(this.clients.values()).map((c) => ({
      id: c.id,
      subscriptions: Array.from(c.subscriptions),
      userId: c.userId,
    }));
  }
}

// Main
async function main() {
  const server = new NotificationServer(config.port);
  await server.start();

  // Keep process alive
  process.on("SIGTERM", () => {
    log.info("Shutting down WebSocket server");
    process.exit(0);
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
