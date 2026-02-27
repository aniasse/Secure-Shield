import { useState, useEffect } from "react";
import {
  Shield,
  Search,
  AlertTriangle,
  Lightbulb,
  MessageCircle,
  Check,
  X,
  Send,
  Activity,
  Bell,
} from "lucide-react";
import { api, LeakResult, PhishingResult } from "./services/api";

function App() {
  const [page, setPage] = useState<
    "home" | "scanner" | "phishing" | "tips" | "chat" | "dashboard"
  >("home");

  return (
    <>
      <nav className="navbar">
        <h1>
          <Shield size={28} /> SecureShield
        </h1>
        <div className="nav-links">
          <a href="#" onClick={() => setPage("home")}>
            Accueil
          </a>
          <a href="#" onClick={() => setPage("dashboard")}>
            Dashboard
          </a>
          <a href="#" onClick={() => setPage("scanner")}>
            Scanner
          </a>
          <a href="#" onClick={() => setPage("phishing")}>
            Phishing
          </a>
          <a href="#" onClick={() => setPage("tips")}>
            Conseils
          </a>
          <a href="#" onClick={() => setPage("chat")}>
            Assistant
          </a>
        </div>
      </nav>

      <main className="container">
        {page === "home" && <HomePage setPage={setPage} />}
        {page === "dashboard" && <Dashboard />}
        {page === "scanner" && <PrivacyScanner />}
        {page === "phishing" && <PhishingDetector />}
        {page === "tips" && <SecurityTips />}
        {page === "chat" && <CyberChat />}
      </main>
    </>
  );
}

function HomePage({
  setPage,
}: {
  setPage: (
    p: "home" | "scanner" | "phishing" | "tips" | "chat" | "dashboard",
  ) => void;
}) {
  return (
    <div className="hero">
      <h2>Protégez-vous dans le monde numérique</h2>
      <p>
        SecureShield est votre compagnon de sécurité en ligne. Vérifiez si vos
        données ont été compromises, détectez les arnaques, et apprenez à rester
        en sécurité.
      </p>
      <div style={{ display: "flex", gap: "1rem", justifyContent: "center" }}>
        <button
          className="btn btn-primary"
          onClick={() => setPage("dashboard")}
        >
          <Activity size={20} /> Dashboard
        </button>
        <button className="btn btn-secondary" onClick={() => setPage("chat")}>
          <MessageCircle size={20} /> Assistant IA
        </button>
      </div>

      <div className="features-grid" style={{ marginTop: "3rem" }}>
        <div className="feature-card" onClick={() => setPage("dashboard")}>
          <h3>
            <Activity size={20} /> Dashboard
          </h3>
          <p>
            Visualisez votre score de sécurité et les menaces en temps réel.
          </p>
        </div>
        <div className="feature-card" onClick={() => setPage("scanner")}>
          <h3>
            <Search size={20} /> Scanner de fuites
          </h3>
          <p>
            Vérifiez si votre email ou mot de passe a été exposé dans une fuite
            de données.
          </p>
        </div>
        <div className="feature-card" onClick={() => setPage("phishing")}>
          <h3>
            <AlertTriangle size={20} /> Détection de phishing
          </h3>
          <p>Analysez des URLs suspectes pour savoir si c'est une arnaque.</p>
        </div>
        <div className="feature-card" onClick={() => setPage("tips")}>
          <h3>
            <Lightbulb size={20} /> Conseils de sécurité
          </h3>
          <p>
            Apprenez les meilleures pratiques pour protéger votre vie numérique.
          </p>
        </div>
      </div>
    </div>
  );
}

function Dashboard() {
  const [stats, setStats] = useState({ alerts: 0, threats: 0, protected: 0 });
  const [riskScore, setRiskScore] = useState<{
    overall: number;
    categories: Record<string, number>;
    trend: string;
  } | null>(null);
  const [alerts, setAlerts] = useState<Record<string, unknown>[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [statsData, riskData, alertsData] = await Promise.all([
          api.getSecurityStats(),
          api.getRiskScore(),
          api.getRecentAlerts(5),
        ]);
        setStats(statsData);
        setRiskScore(riskData);
        setAlerts(alertsData);
      } catch (e) {
        console.error("Failed to load dashboard data", e);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
      </div>
    );
  }

  return (
    <div>
      <h2 style={{ marginBottom: "1.5rem" }}>Dashboard de sécurité</h2>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="value">{stats.alerts}</div>
          <div className="label">Alertes</div>
        </div>
        <div className="stat-card">
          <div className="value" style={{ color: "#ef4444" }}>
            {stats.threats}
          </div>
          <div className="label">Menaces</div>
        </div>
        <div className="stat-card">
          <div className="value">{stats.protected}</div>
          <div className="label">Protégés</div>
        </div>
      </div>

      {riskScore && (
        <div className="feature-card" style={{ marginBottom: "1.5rem" }}>
          <h3>Score de risque</h3>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: "1rem",
              marginTop: "1rem",
            }}
          >
            <div
              style={{
                fontSize: "3rem",
                fontWeight: "bold",
                color:
                  riskScore.overall > 60
                    ? "#10b981"
                    : riskScore.overall > 30
                      ? "#f59e0b"
                      : "#ef4444",
              }}
            >
              {riskScore.overall}%
            </div>
            <div>
              <p>
                Tendance:{" "}
                <strong>
                  {riskScore.trend === "increasing"
                    ? "↑ En hausse"
                    : riskScore.trend === "decreasing"
                      ? "↓ En baisse"
                      : "→ Stable"}
                </strong>
              </p>
              <div
                style={{ display: "flex", gap: "0.5rem", marginTop: "0.5rem" }}
              >
                {Object.entries(riskScore.categories).map(([cat, score]) => (
                  <span
                    key={cat}
                    className={`status-badge ${score > 50 ? "danger" : score > 30 ? "warning" : "success"}`}
                  >
                    {cat}: {score}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="feature-card">
        <h3>
          <Bell size={20} /> Alertes récentes
        </h3>
        <div style={{ marginTop: "1rem" }}>
          {alerts.map((alert: Record<string, unknown>, i) => (
            <div
              key={i}
              style={{
                padding: "0.75rem",
                borderBottom:
                  i < alerts.length - 1 ? "1px solid #e5e7eb" : "none",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <span>{(alert.type as string)?.replace("_", " ")}</span>
              <span
                className={`status-badge ${(alert.severity as number) > 3 ? "danger" : (alert.severity as number) > 2 ? "warning" : "success"}`}
              >
                {alert.severity as number}/5
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function PrivacyScanner() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<LeakResult | null>(null);

  const checkEmail = async () => {
    if (!email || !email.includes("@")) return;
    setLoading(true);
    setResult(null);

    try {
      const data = await api.checkEmailLeak(email);
      setResult(data);
    } catch (e) {
      console.error("Failed to check email", e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: "1.5rem" }}>Scanner de confidentialité</h2>
      <div className="feature-card">
        <p style={{ marginBottom: "1rem" }}>
          Entrez votre adresse email pour vérifier si elle a été exposée dans
          des fuites de données. Ce service utilise l'API Have I Been Pwned pour
          une recherche réaliste.
        </p>
        <div className="input-group">
          <label>Adresse email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="votre@email.com"
            onKeyPress={(e) => e.key === "Enter" && checkEmail()}
          />
        </div>
        <button
          className="btn btn-primary"
          onClick={checkEmail}
          disabled={loading || !email}
        >
          {loading ? "Analyse en cours..." : "Vérifier"}
        </button>

        {result && (
          <div className={`result-card ${result.found ? "danger" : "success"}`}>
            <h3
              style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
            >
              {result.found ? (
                <X size={24} color="#ef4444" />
              ) : (
                <Check size={24} color="#10b981" />
              )}
              {result.found ? "Attention!" : "Bonne nouvelle!"}
            </h3>
            <p style={{ marginTop: "0.5rem" }}>
              {result.found
                ? `Votre email a été trouvé dans ${result.leaks} fuite(s) de données connues. Nous vous recommandons de changer votre mot de passe immédiatement.`
                : "Votre email n'a pas été trouvé dans les fuites de données connues. Continuez à être vigilant!"}
            </p>
            {result.found && (
              <div style={{ marginTop: "1rem" }}>
                <h4>Recommandations:</h4>
                <ul style={{ marginTop: "0.5rem", paddingLeft: "1.5rem" }}>
                  <li>Changez votre mot de passe immédiatement</li>
                  <li>Activez l'authentification à deux facteurs</li>
                  <li>Utilisez un gestionnaire de mots de passe</li>
                  <li>
                    Vérifiez vos autres comptes pour des activités suspectes
                  </li>
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function PhishingDetector() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PhishingResult | null>(null);

  const checkUrl = async () => {
    if (!url) return;
    setLoading(true);
    setResult(null);

    try {
      const data = await api.checkPhishing(url);
      setResult(data);
    } catch (e) {
      console.error("Failed to check URL", e);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: "1.5rem" }}>Détecteur de phishing</h2>
      <div className="feature-card">
        <p style={{ marginBottom: "1rem" }}>
          Collez une URL suspecte pour vérifier si c'est une tentative de
          phishing.
        </p>
        <div className="input-group">
          <label>URL à analyser</label>
          <input
            type="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://..."
            onKeyPress={(e) => e.key === "Enter" && checkUrl()}
          />
        </div>
        <button
          className="btn btn-primary"
          onClick={checkUrl}
          disabled={loading || !url}
        >
          {loading ? "Analyse en cours..." : "Analyser"}
        </button>

        {result && (
          <div
            className={`result-card ${result.isPhishing ? "danger" : "success"}`}
          >
            <h3
              style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
            >
              {result.isPhishing ? (
                <AlertTriangle size={24} color="#ef4444" />
              ) : (
                <Check size={24} color="#10b981" />
              )}
              {result.isPhishing ? "Phishing détecté!" : "URL sécurisée"}
            </h3>
            <p style={{ marginTop: "0.5rem" }}>
              Confiance: {result.confidence}%
            </p>
            <ul style={{ marginTop: "1rem", paddingLeft: "1.5rem" }}>
              {result.reasons.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>
            {result.isPhishing && (
              <div style={{ marginTop: "1rem" }}>
                <h4>Que faire?</h4>
                <ul style={{ marginTop: "0.5rem", paddingLeft: "1.5rem" }}>
                  <li>Ne cliquez pas sur cette URL</li>
                  <li>Ne partagez pas d'informations personnelles</li>
                  <li>Signalez cette URL aux autorités</li>
                </ul>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function SecurityTips() {
  const tips = [
    {
      title: "Utilisez un mot de passe unique",
      desc: "Chaque compte doit avoir son propre mot de passe. Un piratage ne compromettra pas tous vos comptes.",
    },
    {
      title: "Activez l'authentification à 2 facteurs",
      desc: "L'2FA ajoute une couche de sécurité supplémentaire. Utilisez une app comme Google Authenticator.",
    },
    {
      title: "Vérifiez les URLs avant de cliquer",
      desc: "Survolez les liens pour voir où ils mènent vraiment. Méfiez-vous des domaines similaires.",
    },
    {
      title: "Mettez à jour vos logiciels",
      desc: "Les mises à jour corrigent souvent des failles de sécurité importantes. Ne les reportez pas.",
    },
    {
      title: "Utilisez un gestionnaire de mots de passe",
      desc: "Bitwarden, 1Password ou Dashlane peuvent générer et mémoriser des mots de passe forts.",
    },
    {
      title: "Faites attention au WiFi public",
      desc: "Évitez de consulter des sites sensibles sur des réseaux non sécurisés. Utilisez un VPN.",
    },
    {
      title: "Sauvegardez vos données",
      desc: "Faites des sauvegardes régulières sur un disque externe ou un cloud sécurisé.",
    },
    {
      title: "Vérifiez les permissions des apps",
      desc: "Revoyez régulièrement les permissions accordées à vos applications mobiles.",
    },
  ];

  return (
    <div>
      <h2 style={{ marginBottom: "1.5rem" }}>Conseils de sécurité</h2>
      <div className="tips-list">
        {tips.map((tip, i) => (
          <div key={i} className="tip-item">
            <Lightbulb size={24} color="#10b981" />
            <div>
              <strong>{tip.title}</strong>
              <p>{tip.desc}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function CyberChat() {
  const [messages, setMessages] = useState<
    { role: "user" | "bot"; content: string }[]
  >([
    {
      role: "bot",
      content:
        "Bonjour! Je suis l'assistant cyberPeace alimenté par l'IA de SecureShield. Comment puis-vous vous aider à rester en sécurité en ligne? Posez-moi vos questions sur:\n\n• Mot de passe et authentification\n• Phishing et arnaques\n• Protection des données\n• Sécurité mobile\n• Et plus encore!",
    },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);

  const sendMessage = async () => {
    if (!input.trim()) return;
    const userMsg = { role: "user" as const, content: input };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const response = await api.chatWithAI(input);
      setMessages((prev) => [...prev, { role: "bot", content: response }]);
    } catch (e) {
      console.error("Chat error", e);
      setMessages((prev) => [
        ...prev,
        {
          role: "bot",
          content: "Désolé, une erreur est survenue. Veuillez réessayer.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2 style={{ marginBottom: "1.5rem" }}>Assistant cyberPeace</h2>
      <div className="chat-container">
        <div className="chat-messages">
          {messages.map((m, i) => (
            <div key={i} className={`chat-message ${m.role}`}>
              {m.content.split("\n").map((line, j) => (
                <p key={j}>{line}</p>
              ))}
            </div>
          ))}
          {loading && (
            <div className="loading">
              <div className="spinner"></div>
            </div>
          )}
        </div>
        <div className="chat-input">
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={(e) => e.key === "Enter" && !loading && sendMessage()}
            placeholder="Posez votre question sur la sécurité..."
            disabled={loading}
          />
          <button
            className="btn btn-primary"
            onClick={sendMessage}
            disabled={loading}
          >
            <Send size={18} />
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;
