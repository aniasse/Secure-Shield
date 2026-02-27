import { useState } from "react";
import {
  Shield,
  Search,
  AlertTriangle,
  Lightbulb,
  MessageCircle,
  Check,
  X,
  Send,
} from "lucide-react";

function App() {
  const [page, setPage] = useState<
    "home" | "scanner" | "phishing" | "tips" | "chat"
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
  setPage: (p: "home" | "scanner" | "phishing" | "tips" | "chat") => void;
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
        <button className="btn btn-primary" onClick={() => setPage("scanner")}>
          <Search size={20} /> Scanner de confidentialité
        </button>
        <button className="btn btn-secondary" onClick={() => setPage("chat")}>
          <MessageCircle size={20} /> Assistant IA
        </button>
      </div>

      <div className="features-grid" style={{ marginTop: "3rem" }}>
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
        <div className="feature-card" onClick={() => setPage("chat")}>
          <h3>
            <MessageCircle size={20} /> Assistant cyberPeace
          </h3>
          <p>Posez vos questions en langage naturel à notre assistant IA.</p>
        </div>
      </div>
    </div>
  );
}

function PrivacyScanner() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    leaks: number;
    status: string;
  } | null>(null);

  const checkEmail = async () => {
    if (!email) return;
    setLoading(true);
    await new Promise((r) => setTimeout(r, 1500));
    const leaks = Math.floor(Math.random() * 10);
    setResult({ leaks, status: leaks > 0 ? "danger" : "success" });
    setLoading(false);
  };

  return (
    <div>
      <h2 style={{ marginBottom: "1.5rem" }}>Scanner de confidentialité</h2>
      <div className="feature-card">
        <p style={{ marginBottom: "1rem" }}>
          Entrez votre adresse email pour vérifier si elle a été exposée dans
          des fuites de données.
        </p>
        <div className="input-group">
          <label>Adresse email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="votre@email.com"
          />
        </div>
        <button
          className="btn btn-primary"
          onClick={checkEmail}
          disabled={loading}
        >
          {loading ? "Analyse en cours..." : "Vérifier"}
        </button>

        {result && (
          <div className={`result-card ${result.status}`}>
            <h3
              style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}
            >
              {result.leaks > 0 ? (
                <X size={24} color="#ef4444" />
              ) : (
                <Check size={24} color="#10b981" />
              )}
              {result.leaks > 0 ? "Attention!" : "Bonne nouvelle!"}
            </h3>
            <p style={{ marginTop: "0.5rem" }}>
              {result.leaks > 0
                ? `Votre email a été trouvé dans ${result.leaks} fuite(s) de données.`
                : "Votre email n'a pas été trouvé dans les fuites de données connues."}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

function PhishingDetector() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<{
    isPhishing: boolean;
    confidence: number;
    reasons: string[];
  } | null>(null);

  const checkUrl = async () => {
    if (!url) return;
    setLoading(true);
    await new Promise((r) => setTimeout(r, 2000));
    const isPhishing = Math.random() > 0.5;
    setResult({
      isPhishing,
      confidence: Math.floor(Math.random() * 30) + 70,
      reasons: isPhishing
        ? ["URL suspecte", "Domaine récemment créé"]
        : ["Certificat valide", "Domaine de confiance"],
    });
    setLoading(false);
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
          />
        </div>
        <button
          className="btn btn-primary"
          onClick={checkUrl}
          disabled={loading}
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
      desc: "Chaque compte doit avoir son propre mot de passe.",
    },
    {
      title: "Activez l'authentification à 2 facteurs",
      desc: "L'2FA ajoute une couche de sécurité supplémentaire.",
    },
    {
      title: "Vérifiez les URLs avant de cliquer",
      desc: "Survolez les liens pour voir où ils mènent vraiment.",
    },
    {
      title: "Mettez à jour vos logiciels",
      desc: "Les mises à jour corrigent souvent des failles de sécurité.",
    },
    {
      title: "Utilisez un gestionnaire de mots de passe",
      desc: "Cela aide à créer et mémoriser des mots de passe forts.",
    },
    {
      title: "Faites attention au WiFi public",
      desc: "Évitez de consulter des sites sensibles sur des réseaux non sécurisés.",
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
        "Bonjour! Je suis l'assistant cyberPeace. Comment puis-vous vous aider?",
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
    await new Promise((r) => setTimeout(r, 1500));
    const responses: Record<string, string> = {
      "mot de passe":
        "Un bon mot de passe doit contenir au moins 12 caractères.",
      phishing:
        "Le phishing est une technique d'arnaque. Méfiez-vous des emails urgents!",
      virus:
        "Utilisez un antivirus et faites attention à ce que vous téléchargez.",
    };
    let response =
      responses.default ||
      "Je vous recommande de consulter nos conseils de sécurité.";
    for (const key of Object.keys(responses)) {
      if (input.toLowerCase().includes(key)) {
        response = responses[key];
        break;
      }
    }
    setMessages((prev) => [...prev, { role: "bot", content: response }]);
    setLoading(false);
  };

  return (
    <div>
      <h2 style={{ marginBottom: "1.5rem" }}>Assistant cyberPeace</h2>
      <div className="chat-container">
        <div className="chat-messages">
          {messages.map((m, i) => (
            <div key={i} className={`chat-message ${m.role}`}>
              {m.content}
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
            onKeyPress={(e) => e.key === "Enter" && sendMessage()}
            placeholder="Posez votre question..."
          />
          <button className="btn btn-primary" onClick={sendMessage}>
            <Send size={18} />
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;
