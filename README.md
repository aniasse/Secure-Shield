# SECURE SHIELD

**Plateforme de Sécurité Opérationnelle pour SOC-as-a-Service**

---

## 🚀 Démarrage Rapide

### Prérequis

- Docker & Docker Compose (v24.0+)
- 16GB RAM minimum (recommandé 32GB pour production)
- 500GB SSD (recommandé 1TB pour production)
- Node.js v18+ (pour développement)
- Python 3.9+ (pour ML/AI)
- Git

### Installation

```bash
# 1. Cloner le projet
git clone https://github.com/aniasse/afri-secure-shield.git
cd afri-secure-shield

# 2. Copier et configurer les variables d'environnement
cp .env.example .env
# Éditer .env avec vos configurations

# 3. Installer les dépendances (développement)
npm install
pip install -r requirements.txt

# 4. Lancer l'infrastructure
# Mode développement
docker-compose -f docker-compose.dev.yml up -d
# Mode production
docker-compose -f docker-compose.prod.yml up -d

# 5. Vérifier les services
docker-compose ps

# 6. Vérifier les logs
docker-compose logs -f
```



### Accès aux Services

| Service      | URL                   | Port     | Description                     |
| ------------ | --------------------- | -------- | ------------------------------- |
| API Gateway  | http://localhost:8000 | 8000     | Point d'entrée unique          |
| SIEM API     | http://localhost:8080 | 8080     | Gestion des logs et alertes     |
| Threat Intel | http://localhost:8081 | 8081     | Intelligence sur les menaces    |
| SOAR Engine  | http://localhost:8082 | 8082     | Orchestration et automatisation |
| ML Detector  | http://localhost:8083 | 8083     | Détection par IA               |
| Kibana       | http://localhost:5601 | 5601     | Visualisation des logs          |
| Grafana      | http://localhost:3000 | 3000     | Dashboards                      |
| Prometheus   | http://localhost:9090 | 9090     | Métriques                       |
| Dashboard    | http://localhost:3001 | 3001     | Interface web                   |

### Comptes par défaut

| Service      | Username | Password |
| ------------ | -------- | -------- |
| Grafana      | admin    | admin    |
| Kibana       | admin    | changeme |
| API Gateway  | admin    | changeme |

**Important**: Changez les mots de passe par défaut en production!

---

## 📡 API Endpoints

### SIEM Service

```bash
# Rechercher des logs
GET /api/v1/logs?q=error&from=2024-01-01&to=2024-01-31

# Lister les alertes
GET /api/v1/alerts?severity=8&status=new

# Mettre à jour une alerte
PATCH /api/v1/alerts/{id}
{
  "status": "in_progress",
  "assigned_to": "analyst@afri-secure.com"
}

# Statistiques
GET /api/v1/stats
```

### Threat Intelligence

```bash
# Rechercher un indicateur
GET /api/v1/threat-intel/search?q=malicious&type=ip

# Vérifier la réputation
GET /api/v1/threat-intel/check/ip?value=192.168.1.100

# Liste des CVEs récents
GET /api/v1/threat-intel/cves/recent?days=7

# Acteurs de menace
GET /api/v1/threat-intel/actors
```

### SOAR

```bash
# Liste des playbooks
GET /api/v1/soar/playbooks

# Créer un playbook
POST /api/v1/soar/playbooks
{
  "name": "Ransomware Response",
  "description": "Automated ransomware incident response",
  "trigger": {
    "type": "alert_type",
    "condition": { "type": "ransomware" }
  },
  "steps": [
    {
      "id": "isolate",
      "name": "Isoler l'hôte",
      "action": {
        "type": "isolate",
        "target": "edr",
        "operation": "isolate_host",
        "parameters": { "hostname": "${alert.hostname}" }
      }
    }
  ],
  "enabled": true
}

# Exécuter un playbook manuellement
POST /api/v1/soar/playbooks/{id}/run
{
  "hostname": "server-01",
  "severity": 10
}

# Historique des exécutions
GET /api/v1/soar/executions?status=failed
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    SECURE SHIELD                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │
│   │  SIEM   │  │   TI    │  │  SOAR   │  │   ML    │    │
│   │ Service │  │ Service │  │ Engine  │  │Detector │    │
│   └────┬────┘  └────┬────┘  └────┬────┘  └────┬────┘    │
│        │            │            │            │           │
│        └────────────┴─────┬──────┴────────────┘           │
│                          │                                 │
│                    ┌─────▼─────┐                          │
│                    │   Kafka   │                          │
│                    └─────┬─────┘                          │
│                          │                                 │
│        ┌─────────────────┼─────────────────┐              │
│        │                 │                 │              │
│   ┌────▼────┐      ┌─────▼─────┐    ┌────▼────┐        │
│   │Elastic  │      │   Redis   │    │Prometheus│        │
│   │Search   │      │   Cache   │    │ Metrics  │        │
│   └─────────┘      └───────────┘    └──────────┘        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔒 Sécurité

### Authentification

```bash
# Obtenir un token JWT
POST /api/v1/auth/login
{
  "email": "analyst@afri-secure.com",
  "password": "****"
}

# Utiliser le token
curl -H "Authorization: Bearer <token>" \
  http://localhost:8080/api/v1/alerts
```

### Rôles

| Rôle      | Permissions               |
| --------- | ------------------------- |
| `admin`   | Accès complet             |
| `analyst` | Lecture + gestion alertes |
| `viewer`  | Lecture seule             |

---

## 📊 Exemple d'Utilisation

### 1. Recevoir des logs

```bash
# Envoyer un log via l'API
curl -X POST http://localhost:8080/api/v1/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source": "firewall",
    "source_ip": "192.168.1.100",
    "dest_ip": "8.8.8.8",
    "action": "allow",
    "protocol": "tcp",
    "timestamp": "2024-01-15T10:30:00Z"
  }'
```

### 2. Détection automatique

Le système détectera automatiquement:

- Attaques brute force (5+ échecs)
- Connexions suspectes (ports inhabituels)
- Escalade de privilèges
- IPs malveillantes (via Threat Intel)

### 3. Réponse automatisée

```yaml
# Exemple de playbook: Réponse aux ransomwares
playbook:
  name: Ransomware Response
  trigger:
    type: severity
    condition: { min_severity: 9 }
  steps:
    - id: isolate
      action: { target: edr, operation: isolate_host }
    - id: block_c2
      action: { target: firewall, operation: block_ip }
    - id: notify
      action: { target: slack, operation: notify }
    - id: ticket
      action: { target: ticketing, operation: create_ticket }
```

---

## 🤝 Contribution

1. Fork le projet
2. Créez une branche (`feature/nom`)
3. Committez vos changements
4. Poussez vers la branche
5. Ouvrez une Pull Request

---

## 📝 Licence

MIT License - Voir LICENSE pour plus de détails.

---

**SECURE SHIELD** - Protégeons l'Afrique numériquement 🛡️
