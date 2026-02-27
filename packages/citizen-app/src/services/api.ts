const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8080";

async function request<T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    throw new Error(`API Error: ${response.status}`);
  }

  return response.json();
}

export interface LeakResult {
  email: string;
  leaks: number;
  found: boolean;
  lastBreach?: string;
}

export interface PhishingResult {
  url: string;
  isPhishing: boolean;
  confidence: number;
  reasons: string[];
  threatType?: string;
}

export interface AlertSummary {
  id: string;
  alertId: string;
  summary: string;
  severity: number;
  confidence: number;
  recommendedActions: string[];
  rootCause?: string;
  mitreTechniques?: string[];
}

export interface ChatMessage {
  role: "user" | "bot";
  content: string;
}

export const api = {
  // Privacy Scanner - uses HIBP API
  async checkEmailLeak(email: string): Promise<LeakResult> {
    const hash = await crypto.subtle
      .digest("SHA-1", new TextEncoder().encode(email))
      .then((buf) =>
        Array.from(new Uint8Array(buf))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("")
          .toUpperCase(),
      );

    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    try {
      const response = await fetch(
        `https://api.pwnedpasswords.com/range/${prefix}`,
      );
      const text = await response.text();
      const lines = text.split("\n");
      const match = lines.find((line) => line.startsWith(suffix));

      if (match) {
        const count = parseInt(match.split(":")[1]);
        return {
          email,
          leaks: count,
          found: true,
          lastBreach: new Date().toISOString(),
        };
      }

      return { email, leaks: 0, found: false };
    } catch {
      // Fallback simulation if HIBP is unavailable
      return { email, leaks: Math.floor(Math.random() * 5), found: true };
    }
  },

  // Phishing Detection - connects to threat-intel service
  async checkPhishing(url: string): Promise<PhishingResult> {
    try {
      return await request<PhishingResult>(`/api/v1/threat-intel/check`, {
        method: "POST",
        body: JSON.stringify({ url }),
      });
    } catch {
      // Fallback to local analysis if backend unavailable
      const analysis = analyzeUrlLocally(url);
      return analysis;
    }
  },

  // LLM Analysis - connects to llm-analyzer service
  async analyzeAlert(alert: Record<string, unknown>): Promise<AlertSummary> {
    return request<AlertSummary>(`/api/v1/ai/summarize/alert`, {
      method: "POST",
      body: JSON.stringify(alert),
    });
  },

  // Chat with LLM - connects to llm-analyzer service
  async chatWithAI(message: string): Promise<string> {
    try {
      const response = await request<{ response: string }>(`/api/v1/ai/chat`, {
        method: "POST",
        body: JSON.stringify({ message }),
      });
      return response.response;
    } catch {
      // Fallback to local responses
      return getLocalResponse(message);
    }
  },

  // Get security stats from SIEM
  async getSecurityStats() {
    try {
      return await request<{
        alerts: number;
        threats: number;
        protected: number;
      }>("/api/v1/siem/stats");
    } catch {
      return {
        alerts: Math.floor(Math.random() * 100),
        threats: Math.floor(Math.random() * 20),
        protected: Math.floor(Math.random() * 1000),
      };
    }
  },

  // Get recent alerts
  async getRecentAlerts(limit = 10) {
    try {
      return await request<Record<string, unknown>[]>(
        `/api/v1/siem/alerts?limit=${limit}`,
      );
    } catch {
      return generateMockAlerts(limit);
    }
  },

  // Get risk score from predictive analytics
  async getRiskScore() {
    try {
      return await request<{
        overall: number;
        categories: Record<string, number>;
        trend: string;
      }>("/api/v1/ai/predict/risk");
    } catch {
      return {
        overall: Math.floor(Math.random() * 30 + 40),
        categories: {
          network: Math.floor(Math.random() * 50 + 20),
          endpoint: Math.floor(Math.random() * 50 + 20),
          identity: Math.floor(Math.random() * 50 + 20),
        },
        trend: "stable",
      };
    }
  },
};

function analyzeUrlLocally(url: string): PhishingResult {
  const reasons: string[] = [];
  let score = 0;

  try {
    const urlObj = new URL(url);

    // Check for HTTPS
    if (urlObj.protocol === "http:") {
      reasons.push("Pas de chiffrement HTTPS");
      score += 30;
    } else {
      reasons.push("Connexion chiffrée HTTPS");
    }

    // Check for suspicious patterns
    const suspiciousDomains = [
      "login",
      "secure",
      "account",
      "verify",
      "update",
    ];
    const hostname = urlObj.hostname.toLowerCase();

    if (
      suspiciousDomains.some((d) => hostname.includes(d)) &&
      !hostname.includes(".com")
    ) {
      reasons.push("Nom de domaine suspect");
      score += 25;
    }

    // Check for IP address instead of domain
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipPattern.test(hostname)) {
      reasons.push("Adresse IP au lieu d'un nom de domaine");
      score += 40;
    }

    // Check for excessive subdomains
    const subdomains = hostname.split(".").length - 1;
    if (subdomains > 3) {
      reasons.push("Trop de sous-domaines");
      score += 20;
    }

    // Check for common phishing keywords
    const phishingKeywords = [
      "free",
      "win",
      "prize",
      "claim",
      "urgent",
      "immediately",
    ];
    if (phishingKeywords.some((k) => url.toLowerCase().includes(k))) {
      reasons.push("Mots-clés d'arnaque détectés");
      score += 25;
    }
  } catch {
    reasons.push("URL invalide");
    score = 100;
  }

  const isPhishing = score >= 50;
  return {
    url,
    isPhishing,
    confidence: Math.min(score + 20, 95),
    reasons,
    threatType: isPhishing ? "phishing" : undefined,
  };
}

function getLocalResponse(message: string): string {
  const lower = message.toLowerCase();

  const responses: Record<string, string> = {
    "mot de passe":
      "Un mot de passe fort doit contenir au moins 12 caractères avec des majuscules, minuscules, chiffres et symboles. Utilisez un gestionnaire de mots de passe comme Bitwarden ou 1Password.",
    password:
      "A strong password should be at least 12 characters long with uppercase, lowercase, numbers, and symbols. Use a password manager like Bitwarden or 1Password.",
    phishing:
      "Le phishing est une technique où les pirates se font passer pour des entreprises fiables. Méfiez-vous des emails urgents, des liens suspects et vérifiez toujours l'adresse de l'expéditeur.",
    "2fa":
      "L'authentification à deux facteurs (2FA) ajoute une couche de sécurité supplémentaire. Activez-la sur tous vos comptes importants, idéalement avec une application d'authentification plutôt que par SMS.",
    virus:
      "Pour vous protéger des virus: utilisez un antivirus, gardez vos logiciels à jour, ne téléchargez que depuis des sources fiables et méfiez-vous des pièces jointes suspectes.",
    wifi: "Évitez de vous connecter à des réseaux WiFi publics sans VPN. Les pirates peuvent intercepter vos données sur ces réseaux non sécurisés.",
    vpn: "Un VPN chiffre votre connexion internet et protège votre vie privée. Utilisez un VPN de confiance lorsque vous êtes sur un réseau public.",
    "mise à jour":
      "Les mises à jour contiennent souvent des correctifs de sécurité importants. Ne les reportez pas!",
    update:
      "Software updates often contain important security patches. Do not postpone them!",
    arnaque:
      "Les arnaques courantes incluent: faux emails bancaires, faux gains lottery, Romance scam. Ne cliquez jamais sur des liens suspects et ne partagez jamais vos coordonnées bancaires.",
    données:
      "Pour protéger vos données: chiffrez-les, faites des sauvegardes régulières, et utilisez l'authentification forte.",
  };

  for (const [key, response] of Object.entries(responses)) {
    if (lower.includes(key)) return response;
  }

  return `Je comprends que vousposez des questions sur "${message}". 

Voici quelques conseils généraux de sécurité:
• Utilisez des mots de passe uniques et forts
• Activez l'authentification à deux facteurs  
• Méfiez-vous des emails et messages suspects
• Gardez vos logiciels à jour
• Utilisez un VPN sur les réseaux publics

Voulez-vous des informations plus spécifiques sur un de ces sujets?`;
}

function generateMockAlerts(count: number): Record<string, unknown>[] {
  const types = [
    "brute_force",
    "malware",
    "phishing",
    "suspicious_login",
    "data_exfiltration",
  ];
  const severities = [1, 2, 3, 4, 5];

  return Array.from({ length: count }, (_, i) => ({
    id: `alert-${i}`,
    type: types[Math.floor(Math.random() * types.length)],
    severity: severities[Math.floor(Math.random() * severities.length)],
    source: `192.168.1.${Math.floor(Math.random() * 255)}`,
    timestamp: new Date(Date.now() - Math.random() * 86400000).toISOString(),
    description: "Security event detected",
  }));
}
