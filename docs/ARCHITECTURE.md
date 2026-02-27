# AFRI SECURE SHIELD

## Plan Stratégique & Architecture Technique Complète

### Version 1.0 | Janvier 2026

---

# TABLE DES MATIÈRES

1. [Vision & Mission](#1-vision--mission)
2. [Analyse du Marché](#2-analyse-du-marché)
3. [Architecture Système](#3-architecture-système)
4. [Stack Technologique](#4-stack-technologique)
5. [Composants Majeurs](#5-composants-majeurs)
6. [Modèle de Déploiement](#6-modèle-de-déploiement)
7. [Sécurité & Conformité](#7-sécurité--conformité)
8. [Plan d'Implémentation](#8-plan-dimplémentation)
9. [Estimation Budgétaire](#9-estimation-budgétaire)
10. [Risques & Mitigation](#10-risques--mitigation)

---

# 1. VISION & MISSION

## 1.1 Vision

**AFRI SECURE SHIELD** est le premier Security Operations Center (SOC) continental d'Afrique de l'Ouest, alimenté par intelligence artificielle, conçu pour protéger les organisations africaines contre les menaces cybernétiques sophistiquées.

## 1.2 Mission

- Fournir une sécurité de niveau entreprise à coût accessible
- Former la prochaine génération d'experts cybersécurité africains
- Créer une communauté de partage deThreat Intelligence africaine
- Réduire la dépendance aux solutions occidentales
- Contribuer à la souveraineté numérique du continent

## 1.3 Valeurs

| Valeur         | Description                                        |
| -------------- | -------------------------------------------------- |
| **Excellence** | Standards internationaux, certifications reconnues |
| **Innovation** | AI/ML前沿, recherche continue                      |
| **Intégrité**  | Éthique, transparence, confiance                   |
| **Impact**     | Résultats mesurables pour les clients              |
| **Inclusion**  | Accès pour tous, formation locale                  |

---

# 2. ANALYSE DU MARCHÉ

## 2.1 Contexte Sénégalais & Africain

### Défis Actuels

```
┌─────────────────────────────────────────────────────────────────┐
│                     CYBERSECURITY EN AFRIQUE                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   [PROBLÈMES]              [STATISTIQUES]                       │
│                                                                  │
│   ┌──────────┐            ┌────────────────────────────┐       │
│   │ Manque  │            │ 68% des entreprises        │       │
│   │ Experts │            │ africaines victimes        │       │
│   │cyber    │            │ d'attaques en 2025        │       │
│   └──────────┘            └────────────────────────────┘       │
│                                                                  │
│   ┌──────────┐            ┌────────────────────────────┐       │
│   │Couts    │            │ $3.5M pertes moyennes      │       │
│   │Prohibitifs│           │ par breach en Afrique     │       │
│   └──────────┘            └────────────────────────────┘       │
│                                                                  │
│   ┌──────────┐            ┌────────────────────────────┐       │
│   │Dépendance│            │ 85% solutions            │       │
│   │Occident  │            │ importées                 │       │
│   └──────────┘            └────────────────────────────┘       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Opportunités

- **Marché en croissance**: +15%/an sur le segment SOC-as-a-Service
- **Transformation digitale**: Plus de startups tech africaines
- **Réglementation**: NIS2, directives gov sur la sécurité
- **Talent local**: Developers Sénégalais qualifiés disponibles

## 2.2 Segment Cible

| Segment                            | Taille Marché | Potentiel |
| ---------------------------------- | ------------- | --------- |
| Banques & Institutions financières | 45%           | ★★★★★     |
| Opérateurs télécom                 | 20%           | ★★★★☆     |
| Gouvernements & Administration     | 15%           | ★★★★☆     |
| Startups/Tech                      | 10%           | ★★★★★     |
| PME/PMI                            | 10%           | ★★★☆☆     |

---

# 3. ARCHITECTURE SYSTÈME

## 3.1 Vue d'Ensemble

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AFRI SECURE SHIELD - ARCHITECTURE                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                              USERS & CLIENTS                                  │
│         ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐       │
│         │ Analyst  │   │   SOC    │   │   CISO   │   │  DevOps   │       │
│         │ Console  │   │   API    │   │   Dash   │   │  Portal   │       │
│         └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘       │
│              │              │              │              │                │
│              └──────────────┴──────────────┴──────────────┘                │
│                                     │                                         │
│                                     ▼                                         │
│     ┌─────────────────────────────────────────────────────────────────────┐  │
│     │                        API GATEWAY / LOAD BALANCER                  │  │
│     │                    (Kong / Traefik + OAuth2 + Rate Limiting)      │  │
│     └─────────────────────────────────────────────────────────────────────┘  │
│                                      │                                         │
│     ┌────────────────────────────────┴────────────────────────────────────┐  │
│     │                         SERVICES LAYER                              │  │
│     │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐    │  │
│     │  │   SIEM     │ │  Threat    │ │    SOAR    │ │   IAM/SSO   │    │  │
│     │  │  Service   │ │  Intel     │ │  Engine    │ │   Service   │    │  │
│     │  │            │ │  Service   │ │            │ │             │    │  │
│     │  └────────────┘ └────────────┘ └────────────┘ └────────────┘    │  │
│     │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐    │  │
│     │  │  Sandbox   │ │  Fraud     │ │   Audit    │ │  Training   │    │  │
│     │  │  Service   │ │  Detection │ │   Logs     │ │   Academy   │    │  │
│     │  └────────────┘ └────────────┘ └────────────┘ └────────────┘    │  │
│     └────────────────────────────────────────────────────────────────────┘  │
│                                      │                                         │
│     ┌────────────────────────────────┴────────────────────────────────────┐  │
│     │                          DATA LAYER                                 │  │
│     │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐    │  │
│     │  │  Elastic   │ │   Redis    │ │ TimescaleDB│ │  MinIO/    │    │  │
│     │  │   Search   │ │   Cache    │ │  Metrics   │ │   S3       │    │  │
│     │  │   (Logs)    │ │            │ │            │ │  (Files)   │    │  │
│     │  └────────────┘ └────────────┘ └────────────┘ └────────────┘    │  │
│     └────────────────────────────────────────────────────────────────────┘  │
│                                      │                                         │
│     ┌────────────────────────────────┴────────────────────────────────────┐  │
│     │                     INFRASTRUCTURE LAYER                            │  │
│     │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐      │  │
│     │  │   Kubernetes│ │  Docker    │ │ Terraform  │ │  Ansible   │      │  │
│     │  │   (K3s)    │ │  Compose   │ │            │ │            │      │  │
│     │  └────────────┘ └────────────┘ └────────────┘ └────────────┘      │  │
│     └────────────────────────────────────────────────────────────────────┘  │
│                                      │                                         │
│     ┌────────────────────────────────┴────────────────────────────────────┐  │
│     │                    EXTERNAL CONNECTIONS                             │  │
│     │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐      │  │
│     │  │   Orange   │ │    Wave    │ │   Gov      │ │   Threat   │      │  │
│     │  │   Money    │ │            │ │   CERT     │ │   Feeds    │      │  │
│     │  └────────────┘ └────────────┘ └────────────┘ └────────────┘      │  │
│     └────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 3.2 Architecture Microservices Détaillée

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SERVICES DETAILS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                        CORE SERVICES                                │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │                                                                       │    │
│  │   [gateway-svc]                                                     │    │
│  │   ├── Rate limiting (1000 req/min par client)                       │    │
│  │   ├── JWT validation                                                │    │
│  │   ├── Request routing                                               │    │
│  │   └── API versioning                                                │    │
│  │                                                                       │    │
│  │   [auth-svc]                                                        │    │
│  │   ├── OAuth2/OIDC provider                                          │    │
│  │   ├── MFA (TOTP, SMS)                                               │    │
│  │   ├── LDAP/AD integration                                           │    │
│  │   └── JWT token issuance                                            │    │
│  │                                                                       │    │
│  │   [tenant-svc]                                                      │    │
│  │   ├── Multi-tenant isolation                                        │    │
│  │   ├── Quota management                                              │    │
│  │   └── Billing integration                                           │    │
│  │                                                                       │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                     SECURITY SERVICES                               │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │                                                                       │    │
│  │   [siem-svc]                                                        │    │
│  │   ├── Log ingestion (Syslog, Beats, API)                           │    │
│  │   ├── Real-time parsing & normalization                            │    │
│  │   ├── Correlation engine (Sigma rules)                             │    │
│  │   ├── ML-based anomaly detection                                   │    │
│  │   └── Alert generation                                              │    │
│  │                                                                       │    │
│  │   [threat-intel-svc]                                                │    │
│  │   ├── OSINT collection (Twitter, Dark web)                         │    │
│  │   ├── MISP integration                                             │    │
│  │   ├── CVE monitoring                                               │    │
│  │   ├── APT indicators                                               │    │
│  │   └── Reputation feeds                                              │    │
│  │                                                                       │    │
│  │   [soar-svc]                                                        │    │
│  │   ├── Playbook engine                                              │    │
│  │   ├── Incident triage automation                                   │    │
│  │   ├── Ticketing integration (Jira, ServiceNow)                    │    │
│  │   └── Response automation (block IP, disable user)                │    │
│  │                                                                       │    │
│  │   [sandbox-svc]                                                     │    │
│  │   ├── Malware detonation (Cuckoo, CAPEv2)                         │    │
│  │   ├── Network behavior analysis                                    │    │
│  │   ├── YARA rules scanning                                          │    │
│  │   └── Reporting                                                     │    │
│  │                                                                       │    │
│  │   [fraud-svc]                                                       │    │
│  │   ├── Transaction monitoring                                       │    │
│  │   ├── Behavioral analytics                                         │    │
│  │   ├── Rule engine                                                  │    │
│  │   └── Real-time alerts                                              │    │
│  │                                                                       │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │                     SUPPORT SERVICES                               │    │
│  ├────────────────────────────────────────────────────────────────────┤    │
│  │                                                                       │    │
│  │   [notification-svc]                                               │    │
│  │   ├── Email (SMTP)                                                 │    │
│  │   ├── SMS (Orange)                                                 │    │
│  │   ├── WhatsApp Business API                                        │    │
│  │   └── Push notifications                                           │    │
│  │                                                                       │    │
│  │   [audit-svc]                                                      │    │
│  │   ├── Immutable audit trail                                        │    │
│  │   ├── Compliance reporting (SOC2, ISO27001)                       │    │
│  │   └── Forensic exports                                             │    │
│  │                                                                       │    │
│  │   [ml-svc]                                                          │    │
│  │   ├── Anomaly detection models                                     │    │
│  │   ├── Threat classification                                        │    │
│  │   └── Predictive analytics                                          │    │
│  │                                                                       │    │
│  └────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 3.3 Data Flow Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DATA FLOW - INGESTION TO ACTION                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│    SOURCES                  INGESTION              PROCESSING            │
│    ───────                  ─────────              ──────────            │
│                                                                              │
│  ┌─────────┐            ┌───────────┐         ┌──────────────┐        │
│  │ Firewall│───────────▶│  Fluent   │────────▶│   Kafka      │        │
│  │  Logs   │            │   Bit     │         │   Topic      │        │
│  └─────────┘            └───────────┘         └───────┬────────┘        │
│                                                       │                   │
│  ┌─────────┐            ┌───────────┐                 │                   │
│  │   IDS   │───────────▶│  Zeek    │───────────────▶│                   │
│  │  Alerts │            │  (Bro)   │                 │                   │
│  └─────────┘            └───────────┘                 │                   │
│                                                       │                   │
│  ┌─────────┐            ┌───────────┐                 ▼                   │
│  │   EDR   │───────────▶│  Custom   │────────▶┌──────────────┐        │
│  │  Agents │            │  Agent    │         │   Processing  │        │
│  └─────────┘            └───────────┘         │    Pipeline   │        │
│                                               └───────┬────────┘        │
│  ┌─────────┐            ┌───────────┐                 │                   │
│  │   WAF   │───────────▶│  API      │───────────────▶│                   │
│  │  Logs   │            │  Gateway  │                 │                   │
│  └─────────┘            └───────────┘                 ▼                   │
│                                               ┌──────────────┐        │
│  ┌─────────┐            ┌───────────┐         │   Elastic    │        │
│  │ Cloud   │───────────▶│  Lambda   │────────▶│   Search     │        │
│  │  Trails │            │  Functions│         │              │        │
│  └─────────┘            └───────────┘         └───────┬────────┘        │
│                                                       │                   │
│  ┌─────────┐            ┌───────────┐                 │                   │
│  │  App    │───────────▶│  Beats    │────────────────▶│                   │
│  │  Logs   │            │           │                 │                   │
│  └─────────┘            └───────────┘                 │                   │
│                                                       ▼                   │
│                                               ┌──────────────┐        │
│  ┌─────────┐            ┌───────────┐         │   Timescale │        │
│  │ Network │───────────▶│  Telegraf │────────▶│   DB        │        │
│  │ Flows   │            │           │         │  (Metrics)  │        │
│  └─────────┘            └───────────┘         └──────────────┘        │
│                                                                       │
│                   DETECTION                    RESPONSE              │
│                   ─────────                    ────────              │
│                         ┌──────────────────┐                         │
│                         │   Detection      │                         │
│                         │   Rules Engine   │                         │
│                         │  (Sigma/Flink)   │                         │
│                         └────────┬─────────┘                         │
│                                  │                                    │
│                         ┌────────▼─────────┐                         │
│                         │    Alert        │                         │
│                         │    Manager      │                         │
│                         └────────┬─────────┘                         │
│                                  │                                    │
│         ┌────────────────────────┼────────────────────────┐         │
│         │                        │                        │         │
│  ┌──────▼──────┐         ┌───────▼───────┐        ┌──────▼──────┐  │
│  │   SOAR      │         │    SOC        │        │   Automated │  │
│  │  Playbooks  │         │    Analyst    │        │   Response  │  │
│  │              │         │   Console     │        │   (Block,   │  │
│  │              │         │               │        │   Disable)  │  │
│  └──────────────┘         └───────────────┘        └──────────────┘  │
│                                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 4. STACK TECHNOLOGIQUE

## 4.1 Vue d'Ensemble

| Catégorie          | Technologie        | Version   | Rôle                 |
| ------------------ | ------------------ | --------- | -------------------- |
| **Container**      | Docker             | 24.x      | Runtime containers   |
| **Orchestration**  | Kubernetes (K3s)   | 1.28      | Orchestration        |
| **Service Mesh**   | Istio              | 1.20      | Traffic management   |
| **API Gateway**    | Kong               | 3.4       | API Gateway          |
| **Database**       | PostgreSQL         | 15.x      | Primary DB           |
| **Time Series**    | TimescaleDB        | 2.13      | Metrics              |
| **Search**         | Elasticsearch      | 8.11      | Log search           |
| **Cache**          | Redis              | 7.2       | Cache/Session        |
| **Message Queue**  | Apache Kafka       | 3.6       | Event streaming      |
| **Log Collection** | Fluent Bit         | 2.2       | Log shipping         |
| **Monitoring**     | Prometheus/Grafana | 2.47/10.2 | Metrics & Dashboards |
| **Tracing**        | Jaeger             | 1.50      | Distributed tracing  |
| **CI/CD**          | GitLab CI          | 16.x      | Pipeline             |

## 4.2 Détail des Composants

### 4.2.1 SIEM Stack

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            SIEM STACK                                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  INGESTION                                                                  │
│  ─────────                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                        FLEUNT BIT / FILEBEAT                        │    │
│  │                                                                       │    │
│  │   Input Plugins:                                                     │    │
│  │   • tail (files)                                                    │    │
│  │   • syslog (network)                                                │    │
│  │   • http (REST API)                                                 │    │
│  │   • tcp/udp (legacy systems)                                        │    │
│  │                                                                       │    │
│  │   Filters:                                                           │    │
│  │   • grok (parsing)                                                  │    │
│  │   • modify (field manipulation)                                     │    │
│  │   • lua (custom processing)                                         │    │
│  │                                                                       │    │
│  │   Output: Kafka                                                     │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  PROCESSING                                                                   │
│  ─────────                                                                   │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     KAFKA CONSUMERS                                  │    │
│  │                                                                       │    │
│  │   ┌────────────────┐  ┌────────────────┐  ┌────────────────┐      │    │
│  │   │  Log Parser    │  │  Normalizer    │  │  Enricher      │      │    │
│  │   │  (Grok)        │  │  (GeoIP, ASN)  │  │  (TI, Asset)   │      │    │
│  │   └────────────────┘  └────────────────┘  └────────────────┘      │    │
│  │                                                                       │    │
│  │   Topics:                                                           │    │
│  │   • logs.raw (par source type)                                      │    │
│  │   • logs.normalized (champ communs)                                 │    │
│  │   • alerts (detections)                                            │    │
│  │   • metrics (performances)                                          │    │
│  │                                                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  STORAGE                                                                       │
│  ───────                                                                       │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      ELASTICSEARCH CLUSTER                           │    │
│  │                                                                       │    │
│  │   Indices (Daily):                                                   │    │
│  │   • logs-network-YYYY.MM.DD                                         │    │
│  │   • logs-firewall-YYYY.MM.DD                                        │    │
│  │   • logs-application-YYYY.MM.DD                                     │    │
│  │   • logs-authentication-YYYY.MM.DD                                  │    │
│  │   • logs-endpoint-YYYY.MM.DD                                        │    │
│  │                                                                       │    │
│  │   Index Lifecycle:                                                   │    │
│  │   • Hot (7 days) -读写                                              │    │
│  │   • Warm (30 days) -只读                                            │    │
│  │   • Cold (90 days) -压缩                                            │    │
│  │   • Delete (365 days)                                               │    │
│  │                                                                       │    │
│  │   Sharding: 3 primaries + 2 replicas                                │    │
│  │                                                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                    │                                         │
│                                    ▼                                         │
│  VISUALISATION                                                                │
│  ─────────────                                                                │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                     KIBANA / GRAFANA                                 │    │
│  │                                                                       │    │
│  │   Dashboards:                                                        │    │
│  │   • Security Overview                                              │    │
│  │   • Threat Landscape                                                │    │
│  │   • Compliance Status                                               │    │
│  │   • Incident Timeline                                               │    │
│  │   • Executive Summary                                               │    │
│  │                                                                       │    │
│  │   Visualizations:                                                   │    │
│  │   • Attack timeline (timeline)                                      │    │
│  │   • Geographic distribution (map)                                   │    │
│  │   • Top threats (bar chart)                                         │    │
│  │   • Severity distribution (pie)                                    │    │
│  │                                                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2.2 Detection Engine

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DETECTION ENGINE                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐  │
│  │                      RULE CORRELATION LAYER                         │  │
│  ├─────────────────────────────────────────────────────────────────────┤  │
│  │                                                                       │  │
│  │   ┌──────────────────┐    ┌──────────────────┐                     │  │
│  │   │    SIGMA RULES   │    │   CUSTOM RULES   │                     │  │
│  │   │                  │    │                  │                     │  │
│  │   │  500+ rules      │    │  Client-specific │                     │  │
│  │   │  MITRE ATT&CK    │    │  Industry-specific│                     │  │
│  │   │  Coverage        │    │  Use cases       │                     │  │
│  │   └────────┬─────────┘    └────────┬─────────┘                     │  │
│  │            │                         │                               │  │
│  │            └────────────┬────────────┘                               │  │
│  │                         │                                             │  │
│  │                         ▼                                             │  │
│  │            ┌────────────────────────┐                                │  │
│  │            │    ElastAlert /        │                                │  │
│  │            │   Watcher              │                                │  │
│  │            └────────────┬───────────┘                                │  │
│  │                         │                                             │  │
│  └─────────────────────────┼───────────────────────────────────────────┘  │
│                            │                                                │
│  ┌─────────────────────────┼───────────────────────────────────────────┐  │
│  │                    ML DETECTION LAYER                                │  │
│  ├─────────────────────────────────────────────────────────────────────┤  │
│  │                                                                       │  │
│  │   ┌──────────────────┐    ┌──────────────────┐                     │  │
│  │   │  Anomaly         │    │  Clustering      │                     │  │
│  │   │  Detection       │    │  (Isolation      │                     │  │
│  │   │                  │    │   Forest)        │                     │  │
│  │   │  • Outliers      │    │                  │                     │  │
│  │   │  • Deviations    │    │  • User behavior │                     │  │
│  │   │  • Statistical   │    │  • Process       │                     │  │
│  │   │    anomalies     │    │    behavior      │                     │  │
│  │   └──────────────────┘    └──────────────────┘                     │  │
│  │                                                                       │  │
│  │   ┌──────────────────┐    ┌──────────────────┐                     │  │
│  │   │  Classification  │    │  NLP             │                     │  │
│  │   │                  │    │  (Phishing,      │                     │  │
│  │   │  • Malware       │    │   Suspicious     │                     │  │
│  │   │  • Benign        │    │   URLs)           │                     │  │
│  │   │  • Suspicious    │    │                  │                     │  │
│  │   └──────────────────┘    └──────────────────┘                     │  │
│  │                                                                       │  │
│  │   Model Training:                                                   │  │
│  │   • Daily batch training on 30 days data                            │  │
│  │   • Online learning for concept drift                               │  │
│  │   • Human feedback loop (analyst confirms)                         │  │
│  │                                                                       │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                            │                                                │
│  ┌─────────────────────────┼───────────────────────────────────────────┐  │
│  │                    ALERT MANAGEMENT                                   │  │
│  ├─────────────────────────────────────────────────────────────────────┤  │
│  │                                                                       │  │
│  │   Alert Fields:                                                      │  │
│  │   • severity (1-10)                                                │  │
│  │   • confidence (0-100%)                                            │  │
│  │   • MITRE ATT&CK technique                                         │  │
│  │   • affected assets                                                │  │
│  │   • IOC list (IPs, domains, hashes)                                │  │
│  │   • recommended actions                                            │  │
│  │                                                                       │  │
│  │   Alert Aggregation:                                               │  │
│  │   • 5 min window for noise reduction                               │  │
│  │   • Grouping by asset/campaign                                     │  │
│  │   • Deduplication                                                  │  │
│  │                                                                       │  │
│  └─────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2.3 SOAR Platform

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SOAR PLATFORM                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      INCIDENT LIFECYCLE                             │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │                                                                       │    │
│  │    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    │    │
│  │    │ DETECT  │───▶│ TRIAGE  │───▶│ ANALYZE │───▶│ RESPOND │    │    │
│  │    └──────────┘    └──────────┘    └──────────┘    └──────────┘    │    │
│  │         │               │               │               │             │    │
│  │         ▼               ▼               ▼               ▼             │    │
│  │    [Automated]    [AI-Assisted]  [Analyst]    [Automated+Manual]    │    │
│  │                                                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      PLAYBOOK ENGINE                                 │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │                                                                       │    │
│  │   Example Playbook: PHISHING RESPONSE                               │    │
│  │                                                                       │    │
│  │   ┌────────┐     ┌────────┐     ┌────────┐     ┌────────┐          │    │
│  │   │ Start  │────▶│Extract │────▶│Query   │────▶│Block   │          │    │
│  │   │        │     │URLs    │     │TI DB   │     │Sender  │          │    │
│  │   └────────┘     └────────┘     └────────┘     └────────┘          │    │
│  │      │                                         │                    │    │
│  │      │            ┌────────┐                   │                    │    │
│  │      └───────────▶│Notify  │───────────────────┘                    │    │
│  │                   │Analyst │                                         │    │
│  │                   └────────┘                                         │    │
│  │                      │                                                │    │
│  │      ┌────────┐      │                                                │    │
│  │      │Delete  │◀─────┘                                                │    │
│  │      │Emails  │                                                       │    │
│  │      └────────┘                                                       │    │
│  │      │                                                                │    │
│  │      ▼                                                                │    │
│  │   ┌────────┐                                                          │    │
│  │   │Create  │────────────────────────────────────────────────────────  │    │
│  │   │Ticket  │                                                         │    │
│  │   └────────┘                                                         │    │
│  │      │                                                                │    │
│  │      ▼                                                                │    │
│  │   ┌────────┐                                                          │    │
│  │   │Close   │                                                          │    │
│  │   │Incident│                                                          │    │
│  │   └────────┘                                                          │    │
│  │                                                                       │    │
│  │   Playbook Templates:                                                 │    │
│  │   • Malware Infection                                               │    │
│  │   • Ransomware Response                                              │    │
│  │   • Data Exfiltration                                               │    │
│  │   • Account Compromise                                              │    │
│  │   • DDoS Mitigation                                                 │    │
│  │   • Insider Threat                                                  │    │
│  │                                                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                      INTEGRATIONS                                    │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │                                                                       │    │
│  │   SECURITY TOOLS              │  IT OPERATIONS                     │    │
│  │   ───────────────              │  ───────────────                    │    │
│  │   • Fortinet                  │  • ServiceNow                       │    │
│  │   • Palo Alto                 │  • Jira                            │    │
│  │   • Cisco                     │  • Slack                           │    │
│  │   • CrowdStrike               │  • Teams                           │    │
│  │   • SentinelOne               │  • PagerDuty                       │    │
│  │                                                                       │    │
│  │   CLOUD & NETWORK            │  THREAT INTEL                      │    │
│  │   ───────────────              │  ───────────────                    │    │
│  │   • AWS                       │  • MISP                             │    │
│  │   • Azure                     │  • AlienVault OTX                   │    │
│  │   • GCP                       │  • VirusTotal                       │    │
│  │   • VMWare                    │  • AbuseIPDB                        │    │
│  │                                                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 4.3 Infrastructure as Code

```yaml
# kubernetes/cluster.yaml
apiVersion: k3s.io/v1
kind: Cluster
metadata:
  name: afri-secure-shield
spec:
  version: v1.28.5+k3s1
  clusterCIDR: 10.42.0.0/16
  serviceCIDR: 10.43.0.0/16
  nodes:
    - name: master-01
      ip: 10.0.1.10
      role: master
      labels:
        node-role: master
        ssd: "true"
    - name: worker-01
      ip: 10.0.1.11
      role: worker
      labels:
        node-role: worker
        elasticsearch: "true"
    - name: worker-02
      ip: 10.0.1.12
      role: worker
      labels:
        node-role: worker
        kafka: "true"
    - name: worker-03
      ip: 10.0.1.13
      role: worker
      labels:
        node-role: worker
        ml: "true"
```

---

# 5. COMPOSANTS MAJEURS

## 5.1 API Gateway (Kong)

```yaml
# kong/services.yaml
_format_version: "3.0"

services:
  - name: siem-api
    url: http://siem-service:8000
    routes:
      - name: siem-routes
        paths:
          - /api/v1/siem
        methods:
          - GET
          - POST
        plugins:
          - name: rate-limiting
            config:
              minute: 100
              policy: redis
              redis_host: redis-master
          - name: jwt
            config:
              key_claim_name: kid
          - name: cors
            config:
              origins:
                - "https://console.afri_secureshield.com"
              methods:
                - GET
                - POST
                - PUT
                - DELETE
              headers:
                - Authorization
                - Content-Type

  - name: threat-intel-api
    url: http://threat-intel-service:8000
    routes:
      - name: ti-routes
        paths:
          - /api/v1/threat-intel
        plugins:
          - name: rate-limiting
            config:
              minute: 1000

  - name: soar-api
    url: http://soar-service:8000
    routes:
      - name: soar-routes
        paths:
          - /api/v1/soar
        plugins:
          - name: rate-limiting
            config:
              minute: 50

consumers:
  - username: soc-analyst
    groups:
      - analysts
  - username: ciso
    groups:
      - executives
  - username: devops
    groups:
      - operators
```

## 5.2 SIEM Service (Go)

```go
// internal/siem/service.go
package siem

import (
    "context"
    "encoding/json"
    "time"

    "github.com/segmentio/kafka-go"
    "github.com/elastic/go-elasticsearch/v8"
    "github.com/redis/go-redis/v9"
)

type Service struct {
    kafkaReader *kafka.Reader
    esClient    *elasticsearch.Client
    redis       *redis.Client
    rulesEngine *RulesEngine
    mlDetector  *MLDetector
}

type LogEvent struct {
    Timestamp    time.Time              `json:"@timestamp"`
    Source       string                 `json:"source"`
    SourceIP     string                 `json:"source_ip"`
    DestinationIP string               `json:"dest_ip"`
    Action       string                 `json:"action"`
    Protocol     string                 `json:"protocol"`
    BytesIn      int64                  `json:"bytes_in"`
    BytesOut     int64                  `json:"bytes_out"`
    User         string                 `json:"user"`
    Hostname     string                 `json:"hostname"`
    Raw          string                 `json:"raw"`
    Metadata     map[string]interface{} `json:"metadata"`
}

type Alert struct {
    ID            string                 `json:"id"`
    Timestamp     time.Time              `json:"timestamp"`
    Severity      int                    `json:"severity"` // 1-10
    Confidence    float64                `json:"confidence"` // 0-100
    Title         string                 `json:"title"`
    Description   string                 `json:"description"`
    MITRETechnique string                `json:"mitre_technique"`
    IOCs          []IOC                 `json:"iocs"`
    AffectedAssets []string              `json:"affected_assets"`
    RecommendedActions []string          `json:"recommended_actions"`
    Status        string                 `json:"status"` // new, in_progress, resolved
    AssignedTo    string                 `json:"assigned_to"`
}

func (s *Service) Start(ctx context.Context) error {
    // Consume from Kafka
    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            default:
                msg, err := s.kafkaReader.FetchMessage(ctx)
                if err != nil {
                    continue
                }

                var event LogEvent
                if err := json.Unmarshal(msg.Value, &event); err != nil {
                    continue
                }

                s.processEvent(ctx, event)
            }
        }
    }()

    return nil
}

func (s *Service) processEvent(ctx context.Context, event LogEvent) {
    // 1. Store in Elasticsearch
    s.storeEvent(ctx, event)

    // 2. Run detection rules
    alerts := s.rulesEngine.Evaluate(event)

    // 3. Run ML detection
    if s.mlDetector.IsAnomalous(event) {
        alerts = append( Alerts, s.mlDetector.CreateAlert(event))
    }

    // 4. Send alerts
    for _, alert := range alerts {
        s.publishAlert(ctx, alert)
    }
}

func (s *Service) storeEvent(ctx context.Context, event LogEvent) error {
    indexName := fmt.Sprintf("logs-%s-%s",
        getIndexType(event.Source),
        event.Timestamp.Format("2006.01.02"))

    _, err := s.esClient.Index(
        indexName,
        strings.NewReader(mustMarshalJSON(event)),
        s.esClient.Index.WithContext(ctx),
        s.esClient.Index.WithDocumentID(event.ID),
    )

    return err
}

func (s *Service) publishAlert(ctx context.Context, alert Alert) {
    // Publish to Kafka alert topic
    alertBytes, _ := json.Marshal(alert)
    s.kafkaWriter.WriteMessages(ctx, kafka.Message{
        Key:   []byte(alert.ID),
        Value: alertBytes,
    })

    // Cache for deduplication
    s.redis.Set(ctx, "alert:"+alert.ID, 1, 24*time.Hour)
}
```

## 5.3 Threat Intelligence Service (Python)

```python
# services/threat_intel/app.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import asyncio
import aiohttp
from datetime import datetime, timedelta

app = FastAPI(title="Threat Intelligence Service")

class Indicator(BaseModel):
    type: str  # ip, domain, hash, url
    value: str
    source: str
    confidence: float
    last_seen: datetime
    tags: List[str] = []

class ThreatActor(BaseModel):
    name: str
    aliases: List[str]
    description: str
    motivation: str
    target_sectors: List[str]
    ttps: List[str]  # MITRE ATT&CK

class CVEManager:
    """CVE monitoring and enrichment"""

    def __init__(self):
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache = {}  # Redis in production

    async def get_cve(self, cve_id: str) -> Optional[dict]:
        """Fetch CVE details from NVD"""
        params = {"cveId": cve_id}

        async with aiohttp.ClientSession() as session:
            async with session.get(self.nvd_api, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return self.parse_nvd_response(data)
        return None

    async def get_recent_cves(self, days: int = 7) -> List[dict]:
        """Get CVEs from last N days"""
        pub_start = datetime.now() - timedelta(days=days)
        pub_end = datetime.now()

        params = {
            "pubStartDate": pub_start.isoformat(),
            "pubEndDate": pub_end.isoformat(),
            "resultsPerPage": 50
        }

        # Implementation...
        return []

class OSINTCollector:
    """Collect threat intel from open sources"""

    SOURCES = [
        {"name": "Twitter", "api": "twitter"},
        {"name": "VirusTotal", "api": "virustotal"},
        {"name": "AlienVault OTX", "api": "otx"},
        {"name": "AbuseIPDB", "api": "abuseipdb"},
        {"name": "Twitter", "api": "twitter"},
    ]

    async def collect_indicators(self, keyword: str) -> List[Indicator]:
        """Search for indicators across OSINT sources"""
        tasks = []
        for source in self.SOURCES:
            tasks.append(self.search_source(source, keyword))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        indicators = []
        for result in results:
            if isinstance(result, list):
                indicators.extend(result)

        return self.deduplicate(indicators)

    async def search_source(self, source: dict, keyword: str) -> List[Indicator]:
        """Search specific OSINT source"""
        # Implementation per source
        pass

class MISPConnector:
    """MISP instance integration"""

    def __init__(self, url: str, api_key: str):
        self.url = url
        self.api_key = api_key

    async def search_events(self, query: str) -> List[dict]:
        """Search MISP events"""
        headers = {"Authorization": api_key}
        # API call implementation
        pass

    async def get_indicator(self, indicator: str) -> Optional[dict]:
        """Get indicator from MISP"""
        pass

@app.get("/api/v1/threat-intel/indicator/{indicator_type}/{value}")
async def get_indicator(indicator_type: str, value: str):
    """Get threat intelligence for an indicator"""
    # 1. Check local cache
    # 2. Query MISP
    # 3. Query external sources
    # 4. Aggregate and return

    return {
        "indicator": value,
        "type": indicator_type,
        "reputation": "malicious",
        "confidence": 85,
        "sources": ["misp", "virustotal", "otx"],
        "last_analysis": datetime.now().isoformat(),
        "tags": ["apt", "c2", "financially-motivated"],
        "related_campaigns": ["APT42"],
        "first_seen": "2024-01-15",
        "last_seen": "2024-02-20"
    }

@app.get("/api/v1/threat-intel/cve/{cve_id}")
async def get_cve(cve_id: str):
    """Get CVE details"""
    manager = CVEManager()
    cve = await manager.get_cve(cve_id)

    if not cve:
        raise HTTPException(status_code=404, detail="CVE not found")

    return cve

@app.get("/api/v1/threat-intel/actors")
async def list_threat_actors(
    motivation: Optional[str] = None,
    target_sector: Optional[str] = None
):
    """List threat actors with filters"""
    # Query from database
    return {
        "actors": [
            {
                "name": "APT42",
                "aliases": ["Lazarus", "Hidden Cobra"],
                "description": "North Korean state-sponsored group",
                "motivation": "financial",
                "target_sectors": ["finance", "government"],
                "ttps": ["T1566", "T1041", "T1486"]
            }
        ],
        "total": 1
    }
```

## 5.4 SOAR Engine (Go)

```go
// internal/soar/engine.go
package soar

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/segmentio/kafka-go"
    "github.com/go-playground/validator"
)

type Playbook struct {
    ID          string     `json:"id" validate:"required"`
    Name        string     `json:"name" validate:"required"`
    Description string     `json:"description"`
    Trigger     Trigger    `json:"trigger"`
    Steps       []Step    `json:"steps"`
    Enabled     bool      `json:"enabled"`
    Version     int       `json:"version"`
}

type Trigger struct {
    Type    string            `json:"type"` // alert_type, schedule, manual
    Condition map[string]interface{} `json:"condition"`
}

type Step struct {
    ID          string      `json:"id" validate:"required"`
    Name        string      `json:"name"`
    Action      Action     `json:"action"`
    Condition   string      `json:"condition"` // jaql expression
    Timeout     int         `json:"timeout"` // seconds
    Retry       Retry      `json:"retry"`
    OnFailure   string      `json:"on_failure"` // continue, stop, rollback
}

type Action struct {
    Type    string                 `json:"type" validate:"required"`
    Target  string                 `json:"target"` // integration name
    Operation string               `json:"operation"`
    Parameters map[string]interface{} `json:"parameters"`
}

type Execution struct {
    ID            string                 `json:"id"`
    PlaybookID    string                 `json:"playbook_id"`
    Status        string                 `json:"status"` // running, completed, failed
    TriggerData   map[string]interface{} `json:"trigger_data"`
    CurrentStep   string                 `json:"current_step"`
    StepResults   []StepResult          `json:"step_results"`
    StartedAt     time.Time              `json:"started_at"`
    CompletedAt   *time.Time             `json:"completed_at"`
    Error         string                 `json:"error,omitempty"`
}

type StepResult struct {
    StepID   string                 `json:"step_id"`
    Status   string                 `json:"status"` // success, failure, skipped
    Output   map[string]interface{} `json:"output"`
    Duration int                    `json:"duration_ms"`
    Error    string                 `json:"error,omitempty"`
}

type Engine struct {
    playwrights   map[string]*Playbook
    integrations IntegrationRegistry
    executor     *Executor
    kafkaWriter  *kafka.Writer
    db           *Database
}

func (e *Engine) Start(ctx context.Context) error {
    // Load playbooks from database
    playbooks, err := e.db.GetActivePlaybooks()
    if err != nil {
        return err
    }

    for _, pb := range playbooks {
        e.playwrights[pb.ID] = pb
    }

    // Subscribe to alert topic
    reader := kafka.NewReader(kafka.ReaderConfig{
        Topic:  "alerts",
        Broker: []string{"kafka:9092"},
        GroupID: "soar-engine",
    })

    go func() {
        for {
            select {
            case <-ctx.Done():
                return
            default:
                msg, err := reader.FetchMessage(ctx)
                if err != nil {
                    continue
                }

                var alert Alert
                if err := json.Unmarshal(msg.Value, &alert); err != nil {
                    continue
                }

                e.triggerPlaybooks(ctx, alert)
            }
        }
    }()

    return nil
}

func (e *Engine) triggerPlaybooks(ctx context.Context, alert Alert) {
    for _, pb := range e.playwrights {
        if !pb.Enabled {
            continue
        }

        if e.matchesTrigger(pb.Trigger, alert) {
            go e.executePlaybook(ctx, pb, alert)
        }
    }
}

func (e *Engine) matchesTrigger(trigger Trigger, alert Alert) bool {
    switch trigger.Type {
    case "alert_type":
        return alert.Type == trigger.Condition["type"]
    case "severity":
        return alert.Severity >= trigger.Condition["min_severity"].(int)
    case "manual":
        return false
    }
    return false
}

func (e *Engine) executePlaybook(ctx context.Context, pb *Playbook, triggerData map[string]interface{}) {
    exec := &Execution{
        ID: generateUUID(),
        PlaybookID: pb.ID,
        Status: "running",
        TriggerData: triggerData,
        StartedAt: time.Now(),
    }

    e.db.SaveExecution(exec)

    for _, step := range pb.Steps {
        exec.CurrentStep = step.ID

        result := e.executeStep(ctx, step, triggerData, exec.StepResults)
        exec.StepResults = append(exec.StepResults, result)

        if result.Status == "failure" {
            if step.OnFailure == "stop" {
                exec.Status = "failed"
                exec.Error = result.Error
                break
            }
        }

        // Update trigger data with step output
        if result.Output != nil {
            for k, v := range result.Output {
                triggerData[fmt.Sprintf("%s.%s", step.ID, k)] = v
            }
        }
    }

    if exec.Status == "running" {
        exec.Status = "completed"
        now := time.Now()
        exec.CompletedAt = &now
    }

    e.db.SaveExecution(exec)
}

func (e *Engine) executeStep(ctx context.Context, step Step, data map[string]interface{}, previousResults []StepResult) StepResult {
    start := time.Now()

    // Evaluate condition
    if step.Condition != "" {
        if !evaluateCondition(step.Condition, data, previousResults) {
            return StepResult{
                StepID: step.ID,
                Status: "skipped",
                Duration: int(time.Since(start).Milliseconds()),
            }
        }
    }

    // Get integration
    integration, ok := e.integrations.Get(step.Action.Target)
    if !ok {
        return StepResult{
            StepID: step.ID,
            Status: "failure",
            Error: "integration not found",
            Duration: int(time.Since(start).Milliseconds()),
        }
    }

    // Prepare parameters
    params := interpolateParameters(step.Action.Parameters, data)

    // Execute with retry
    var lastErr error
    for i := 0; i <= step.Retry.Count; i++ {
        output, err := integration.Execute(ctx, step.Action.Operation, params)
        if err == nil {
            return StepResult{
                StepID: step.ID,
                Status: "success",
                Output: output,
                Duration: int(time.Since(start).Milliseconds()),
            }
        }
        lastErr = err

        if i < step.Retry.Count {
            time.Sleep(time.Duration(step.Retry.Delay) * time.Second)
        }
    }

    return StepResult{
        StepID: step.ID,
        Status: "failure",
        Error: lastErr.Error(),
        Duration: int(time.Since(start).Milliseconds()),
    }
}
```

## 5.5 ML Detection Module (Python)

```python
# services/ml_detector/app.py
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import joblib
from datetime import datetime, timedelta
from collections import deque
import redis

class MLDetector:
    """
    Machine Learning based threat detection
    """

    def __init__(self, model_path: str = "/models"):
        self.model_path = model_path
        self.redis_client = redis.Redis(host='redis', port=6379, db=0)

        # Models
        self.iforest = None
        self.dbscan = None
        self.scaler = StandardScaler()

        # Training window
        self.window_size = 10000
        self.events_buffer = deque(maxlen=self.window_size)

        self.load_models()

    def load_models(self):
        """Load pre-trained models"""
        try:
            self.iforest = joblib.load(f"{self.model_path}/isolation_forest.pkl")
            self.scaler = joblib.load(f"{self.model_path}/scaler.pkl")
        except FileNotFoundError:
            # Initial training will happen
            pass

    def extract_features(self, event: dict) -> np.array:
        """Extract features from log event for ML"""
        features = []

        # Time-based features
        timestamp = datetime.fromisoformat(event['timestamp'])
        features.append(timestamp.hour)
        features.append(timestamp.weekday())

        # Network features
        features.append(self.ip_to_numeric(event.get('source_ip', '0.0.0.0')))
        features.append(self.ip_to_numeric(event.get('dest_ip', '0.0.0.0')))
        features.append(event.get('bytes_in', 0))
        features.append(event.get('bytes_out', 0))
        features.append(event.get('duration', 0))

        # Behavioral features
        features.append(event.get('auth_failures', 0))
        features.append(event.get('unique_hosts', 0))
        features.append(event.get('connections_count', 0))

        # Protocol features
        protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
        features.append(protocol_map.get(event.get('protocol', 'tcp'), 0))

        return np.array(features).reshape(1, -1)

    def is_anomalous(self, event: dict) -> bool:
        """Detect if event is anomalous"""
        if not self.iforest:
            return False

        features = self.extract_features(event)
        features_scaled = self.scaler.transform(features)

        # Get anomaly score
        score = self.iforest.decision_function(features_scaled)

        # Store for threshold learning
        self.redis_client.lpush('anomaly_scores', score[0])

        # Threshold (to be tuned based on data)
        threshold = -0.5

        return score[0] < threshold

    def detect_behavioral_anomalies(self, user_id: str) -> List[dict]:
        """Detect behavioral anomalies for a user"""
        # Get user events from last 24h
        events = self.get_user_events(user_id, hours=24)

        if len(events) < 100:
            return []

        # Extract features for each event
        X = []
        for event in events:
            X.append(self.extract_features(event).flatten())

        X = np.array(X)
        X_scaled = self.scaler.fit_transform(X)

        # DBSCAN clustering
        clusters = self.dbscan.fit_predict(X_scaled)

        # Find outliers (cluster -1)
        outlier_indices = np.where(clusters == -1)[0]

        anomalies = []
        for idx in outlier_indices:
            anomalies.append({
                'event': events[idx],
                'cluster': -1,
                'severity': self.calculate_severity(events[idx])
            })

        return anomalies

    def create_alert(self, event: dict, score: float) -> Alert:
        """Create alert from ML detection"""
        return Alert(
            title=f"ML Anomaly Detected: {event.get('event_type', 'unknown')}",
            severity=self.score_to_severity(score),
            confidence=abs(score) * 100,
            description=f"Anomalous behavior detected with score {score}",
            mitre_technique="T1078.003",  # Valid Accounts: Cloud Accounts
            recommended_actions=[
                "Review user activity",
                "Verify identity",
                "Check for data exfiltration"
            ]
        )

    def retrain(self, feedback: List[dict]):
        """
        Retrain models with analyst feedback
        Called daily or on-demand
        """
        # Collect labeled data from feedback
        X_train = []
        y_train = []

        for item in feedback:
            X_train.append(self.extract_features(item['event']).flatten())
            y_train.append(1 if item['label'] == 'malicious' else 0)

        X_train = np.array(X_train)

        # Update scaler
        self.scaler.fit(X_train)
        X_scaled = self.scaler.transform(X_train)

        # Retrain Isolation Forest
        self.iforest = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        self.iforest.fit(X_scaled)

        # Save models
        joblib.dump(self.iforest, f"{self.model_path}/isolation_forest.pkl")
        joblib.dump(self.scaler, f"{self.model_path}/scaler.pkl")

        # Update threshold based on new data
        scores = self.iforest.decision_function(X_scaled)
        new_threshold = np.percentile(scores, 10)
        self.redis_client.set('anomaly_threshold', new_threshold)


class UserBehaviorAnalyzer:
    """
    Analyze user behavior patterns
    """

    def __init__(self):
        self.redis = redis.Redis(host='redis', port=6379, db=1)
        self.baseline_window = timedelta(days=30)

    def build_baseline(self, user_id: str) -> dict:
        """Build behavioral baseline for user"""
        events = self.get_user_events(user_id, days=30)

        baseline = {
            'login_times': self.analyze_login_times(events),
            'ip_addresses': self.analyze_unique_ips(events),
            'locations': self.analyze_locations(events),
            'device_types': self.analyze_devices(events),
            'access_patterns': self.analyze_access_patterns(events),
            'data_volume': self.analyze_data_volume(events),
        }

        # Store baseline
        self.redis.hset(f'baseline:{user_id}', mapping={
            'data': json.dumps(baseline),
            'updated': datetime.now().isoformat()
        })

        return baseline

    def detect_deviation(self, user_id: str, event: dict) -> List[str]:
        """Detect deviations from baseline"""
        baseline = json.loads(self.redis.hget(f'baseline:{user_id}', 'data'))
        deviations = []

        # Check login time
        event_hour = datetime.fromisoformat(event['timestamp']).hour
        if event_hour not in baseline['login_times']['usual_hours']:
            deviations.append('unusual_login_time')

        # Check IP
        if event.get('source_ip') not in baseline['ip_addresses']['known']:
            deviations.append('new_ip_address')

        # Check location
        if event.get('geo_location') != baseline['locations']['usual']:
            deviations.append('unusual_location')

        # Check data volume
        if event.get('bytes_out', 0) > baseline['data_volume']['avg'] * 3:
            deviations.append('data_exfiltration_possible')

        return deviations
```

---

# 6. MODÈLE DE DÉPLOIEMENT

## 6.1 Architecture Multi-Cloud / Hybrid

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                      MODÈLE DE DÉPLOIEMENT HYBRIDE                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                           ┌───────────────────┐                              │
│                           │    INTERNET       │                              │
│                           │     (WAN)         │                              │
│                           └─────────┬─────────┘                              │
│                                     │                                         │
│         ┌──────────────────────────┼──────────────────────────┐            │
│         │                          │                          │            │
│         ▼                          ▼                          ▼            │
│  ┌──────────────┐          ┌──────────────┐          ┌──────────────┐     │
│  │  ON-PREMISE  │          │    AWS/EU    │          │   ORANGE     │     │
│  │  (Dakar)     │          │   (Region)   │          │   CLOUD      │     │
│  │              │          │              │          │   (SN)       │     │
│  │ ┌──────────┐ │          │ ┌──────────┐  │          │ ┌──────────┐  │     │
│  │ │ SOC      │ │◄────────►│ │ SOC      │  │◄────────►│ │ SOC      │  │     │
│  │ │ Analysts │ │   VPN    │ │ Primary  │  │   Direct │ │ Backup   │  │     │
│  │ └──────────┘ │          │ └──────────┘  │   Link   │ └──────────┘  │     │
│  │              │          │              │          │              │     │
│  │ ┌──────────┐ │          │ ┌──────────┐  │          │ ┌──────────┐  │     │
│  │ │ Data     │ │          │ │ Hot Data │  │          │ │ DR Site  │  │     │
│  │ │ Center   │ │          │ │          │  │          │ │          │  │     │
│  │ └──────────┘ │          │ └──────────┘  │          │ └──────────┘  │     │
│  └──────────────┘          └──────────────┘          └──────────────┘     │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐    │
│  │                         CONNECTIVITY                                 │    │
│  ├─────────────────────────────────────────────────────────────────────┤    │
│  │                                                                       │    │
│  │   Primary:   Orange Fiber 1Gbps (Dakar)                            │    │
│  │   Backup:    Sonatel ADSL 100Mbps                                  │    │
│  │   DR:        AWS Direct Connect / Orange Cloud                     │    │
│  │                                                                       │    │
│  │   VPN:       IPSec tunnel to cloud (redondant)                     │    │
│  │   Bandwidth: 500Mbps continuous sync                               │    │
│  │                                                                       │    │
│  └─────────────────────────────────────────────────────────────────────┘    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 6.2 Déploiement Kubernetes (K3s)

```yaml
# kubernetes/namespaces.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: afri-secure
---
apiVersion: v1
kind: Namespace
metadata:
  name: siem
---
apiVersion: v1
kind: Namespace
metadata:
  name: threat-intel
---
apiVersion: v1
kind: Namespace
metadata:
  name: soar
---
apiVersion: v1
kind: Namespace
metadata:
  name: ml
---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring

---
# kubernetes/elasticsearch.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: elasticsearch-config
  namespace: siem
data:
  elasticsearch.yml: |
    cluster.name: afri-siem
    node.name: ${HOSTNAME}
    discovery.seed_hosts: elasticsearch-0.elasticsearch
    cluster.initial_master_nodes: elasticsearch-0
    network.host: 0.0.0.0
    indices.query.bool.max_clause_count: 8192
    search.max_buckets: 10000
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: elasticsearch
  namespace: siem
spec:
  serviceName: elasticsearch
  replicas: 3
  selector:
    matchLabels:
      app: elasticsearch
  template:
    metadata:
      labels:
        app: elasticsearch
    spec:
      containers:
        - name: elasticsearch
          image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
          env:
            - name: ES_JAVA_OPTS
              value: "-Xms4g -Xmx4g"
          ports:
            - containerPort: 9200
            - containerPort: 9300
          volumeMounts:
            - name: data
              mountPath: /usr/share/elasticsearch/data
            - name: config
              mountPath: /usr/share/elasticsearch/config/elasticsearch.yml
              subPath: elasticsearch.yml
          resources:
            requests:
              cpu: "2"
              memory: 8Gi
            limits:
              cpu: "4"
              memory: 16Gi
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: elasticsearch-data
        - name: config
          configMap:
            name: elasticsearch-config

---
# kubernetes/kafka.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: kafka-config
  namespace: afri-secure
data:
  server.properties: |
    broker.id=0
    listeners=PLAINTEXT://:9092
    advertised.listeners=PLAINTEXT://kafka:9092
    num.network.threads=3
    num.io.threads=8
    socket.send.buffer.bytes=102400
    socket.receive.buffer.bytes=102400
    socket.request.max.bytes=104857600
    log.dirs=/var/lib/kafka/data
    num.partitions=6
    num.recovery.threads.per.data.dir=1
    offsets.topic.replication.factor=3
    transaction.state.log.replication.factor=3
    transaction.state.log.min.isr=2
    log.retention.hours=168
    log.segment.bytes=1073741824
    log.retention.check.interval.ms=300000
    zookeeper.connect=zookeeper:2181
    zookeeper.connection.timeout.ms=18000
    group.initial.rebalance.delay.ms=300

---
# kubernetes/services.yaml
apiVersion: v1
kind: Service
metadata:
  name: siem-api
  namespace: siem
spec:
  selector:
    app: siem-api
  ports:
    - port: 8000
      targetPort: 8000
  type: ClusterIP

---
apiVersion: v1
kind: Service
metadata:
  name: threat-intel-api
  namespace: threat-intel
spec:
  selector:
    app: threat-intel-api
  ports:
    - port: 8000
      targetPort: 8000

---
apiVersion: v1
kind: Service
metadata:
  name: soar-api
  namespace: soar
spec:
  selector:
    app: soar-api
  ports:
    - port: 8000
      targetPort: 8000
```

## 6.3 Configuration des Ingress

```yaml
# kubernetes/ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: afri-secure-ingress
  namespace: afri-secure
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "50m"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "300"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
    nginx.ingress.kubernetes.io/rate-limit: "100"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - console.afri-secureshield.com
        - api.afri-secureshield.com
      secretName: afri-secure-tls
  rules:
    - host: api.afri-secureshield.com
      http:
        paths:
          - path: /siem
            pathType: Prefix
            backend:
              service:
                name: siem-api
                port:
                  number: 8000
          - path: /threat-intel
            pathType: Prefix
            backend:
              service:
                name: threat-intel-api
                port:
                  number: 8000
          - path: /soar
            pathType: Prefix
            backend:
              service:
                name: soar-api
                port:
                  number: 8000
```

---

# 7. SÉCURITÉ & CONFORMITÉ

## 7.1 Architecture Zero Trust

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ZERO TRUST ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│    ┌────────────────────────────────────────────────────────────────────┐  │
│    │                      PERIMETRE SÉCURISÉ                           │  │
│    │                                                                    │  │
│    │  ┌──────────────────────────────────────────────────────────────┐  │  │
│    │  │                    EDGE SECURITY                             │  │  │
│    │  │                                                               │  │  │
│    │  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │  │  │
│    │  │   │   WAF       │    │   DDoS     │    │   CDN       │     │  │  │
│    │  │   │   (ModSec)  │    │   (CloudFlare)│  │   (Cache)  │     │  │  │
│    │  │   └─────────────┘    └─────────────┘    └─────────────┘     │  │  │
│    │  │                                                               │  │  │
│    │  │   ┌─────────────┐    ┌─────────────┐                       │  │  │
│    │  │   │   Rate      │    │   IP        │                       │  │  │
│    │  │   │   Limiting  │    │   Reputation│                       │  │  │
│    │  │   └─────────────┘    └─────────────┘                       │  │  │
│    │  │                                                               │  │  │
│    │  └──────────────────────────────────────────────────────────────┘  │  │
│    │                              │                                      │  │
│    │                              ▼                                      │  │
│    │  ┌──────────────────────────────────────────────────────────────┐  │  │
│    │  │                    IDENTITY & ACCESS                         │  │  │
│    │  │                                                               │  │  │
│    │  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │  │  │
│    │  │   │   IAM/SSO   │    │    MFA      │    │    RBAC     │     │  │  │
│    │  │   │   (Keycloak)│    │   (TOTP)    │    │             │     │  │  │
│    │  │   └─────────────┘    └─────────────┘    └─────────────┘     │  │  │
│    │  │                                                               │  │  │
│    │  │   ┌─────────────┐    ┌─────────────┐                       │  │  │
│    │  │   │   JWT       │    │  Session    │                       │  │  │
│    │  │   │   Validation│    │  Management │                       │  │  │
│    │  │   └─────────────┘    └─────────────┘                       │  │  │
│    │  │                                                               │  │  │
│    │  └──────────────────────────────────────────────────────────────┘  │  │
│    │                              │                                      │  │
│    │                              ▼                                      │  │
│    │  ┌──────────────────────────────────────────────────────────────┐  │  │
│    │  │                    WORKLOAD SECURITY                         │  │  │
│    │  │                                                               │  │  │
│    │  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │  │  │
│    │  │   │   Service   │    │   mTLS      │    │   Network   │     │  │  │
│    │  │   │   Mesh      │    │  (Istio)    │    │  Policies   │     │  │  │
│    │  │   │  (Istio)    │    │             │    │             │     │  │  │
│    │  │   └─────────────┘    └─────────────┘    └─────────────┘     │  │  │
│    │  │                                                               │  │  │
│    │  │   ┌─────────────┐    ┌─────────────┐                       │  │  │
│    │  │   │   Pod       │    │   Secrets   │                       │  │  │
│    │  │   │   Security  │    │  (Vault)    │                       │  │  │
│    │  │   │   Policies  │    │             │                       │  │  │
│    │  │   └─────────────┘    └─────────────┘                       │  │  │
│    │  │                                                               │  │  │
│    │  └──────────────────────────────────────────────────────────────┘  │  │
│    │                              │                                      │  │
│    │                              ▼                                      │  │
│    │  ┌──────────────────────────────────────────────────────────────┐  │  │
│    │  │                    DATA SECURITY                             │  │  │
│    │  │                                                               │  │  │
│    │  │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │  │  │
│    │  │   │   Encryption│    │   Token-    │    │   Data      │     │  │  │
│    │  │   │   at Rest   │    │   ization   │    │   Masking   │     │  │  │
│    │  │   │   (AES-256) │    │             │    │             │     │  │  │
│    │  │   └─────────────┘    └─────────────┘    └─────────────┘     │  │  │
│    │  │                                                               │  │  │
│    │  │   ┌─────────────┐    ┌─────────────┐                       │  │  │
│    │  │   │   Backup    │    │   Audit     │                       │  │  │
│    │  │   │   (Encrypted│    │   Logs      │                       │  │  │
│    │  │   │    + Offsite│    │             │                       │  │  │
│    │  │   └─────────────┘    └─────────────┘                       │  │  │
│    │  │                                                               │  │  │
│    │  └──────────────────────────────────────────────────────────────┘  │  │
│    │                                                                    │  │
│    └────────────────────────────────────────────────────────────────────┘  │
│                                                                              │
│    PRINCIPLES:                                                               │
│    • Never trust, always verify                                             │
│    • Least privilege access                                                 │
│    • Assume breach                                                          │
│    • Verify explicitly                                                      │
│    • Micro-segmentation                                                    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 7.2 Conformité Réglementaire

| Standard              | Requirement             | Implementation       |
| --------------------- | ----------------------- | -------------------- |
| **ISO 27001**         | ISMS                    | Certified in Phase 2 |
| **SOC 2 Type II**     | Security, Availability  | Annual audit         |
| **PCI DSS**           | Payment security        | For fraud module     |
| **GDPR**              | Data privacy            | EU data processing   |
| **NIS2**              | Critical infrastructure | EU compliance        |
| **Local regulations** | Senegal data law        | Data residency       |

---

# 8. PLAN D'IMPLEMENTATION

## 8.1 Roadmap

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ROADMAP - 24 MOIS                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PHASE 1: FOUNDATION (Mois 1-6)                                             │
│  ═══════════════════════════════                                            │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 1-2: Infrastructure Core                                       │   │
│  │ • Déploiement K3s cluster                                            │   │
│  │ • Configuration Kafka, Elasticsearch, Redis                        │   │
│  │ • Mise en place CI/CD (GitLab)                                      │   │
│  │ • Security hardening initial                                         │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 3-4: SIEM Core                                                 │   │
│  │ • Ingestion logs (Firewall, IDS, EDR)                              │   │
│  │ • Detection rules (Sigma)                                           │   │
│  │ • Dashboards Kibana                                                  │   │
│  │ • Alert management                                                   │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 5-6: Threat Intelligence                                       │   │
│  │ • MISP integration                                                   │   │
│  │ • CVE monitoring                                                     │   │
│  │ • OSINT collection                                                   │   │
│  │ • IOC database                                                      │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  PHASE 2: ADVANCED SECURITY (Mois 7-12)                                     │
│  ══════════════════════════════════════                                    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 7-8: SOAR                                                      │   │
│  │ • Playbook engine                                                   │   │
│  │ • Incident response automation                                      │   │
│  │ • Integration (Firewall, EDR, ticketing)                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 9-10: ML Detection                                             │   │
│  │ • Anomaly detection models                                          │   │
│  │ • Behavioral analysis                                               │   │
│  │ • Threat classification                                             │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 11-12: Sandbox & Forensics                                    │   │
│  │ • Malware sandbox (CAPEv2)                                         │   │
│  │ • Digital forensics toolkit                                         │   │
│  │ • Evidence collection                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  PHASE 3: SCALE & AUTOMATE (Mois 13-18)                                     │
│  ══════════════════════════════════════                                    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 13-15: Multi-Tenant                                            │   │
│  │ • Client isolation                                                   │   │
│  │ • Self-service portal                                                │   │
│  │ • Billing integration (Orange Money)                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 16-18: AI & Automation                                         │   │
│  │ • LLM for analyst assistance                                        │   │
│  │ • Automated threat hunting                                          │   │
│  │ • Predictive analytics                                              │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
│  PHASE 4: EXPANSION (Mois 19-24)                                            │
│  ══════════════════════════════════════                                    │
│                                                                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 19-21: Regional Expansion                                      │   │
│  │ • Ghana, Côte d'Ivoire, Mali                                       │   │
│  │ • Local language support (Wolof, Dioula)                           │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              │                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │ Mois 22-24: Certification & Partners                               │   │
│  │ • ISO 27001 certification                                           │   │
│  │ • SOC 2 Type II                                                     │   │
│  │ • Partnership program                                               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## 8.2 Équipe

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         ORGANIGRAMME - ÉQUIPE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│                         ┌─────────────────┐                                  │
│                         │    CEO/FONDATEUR│                                 │
│                         └────────┬────────┘                                  │
│                                  │                                           │
│            ┌─────────────────────┼─────────────────────┐                   │
│            │                     │                     │                    │
│            ▼                     ▼                     ▼                   │
│   ┌────────────────┐    ┌────────────────┐    ┌────────────────┐           │
│   │   OPERATIONS   │    │   TECHNOLOGY   │    │    BUSINESS    │           │
│   │   DIRECTOR    │    │    DIRECTOR    │    │    DIRECTOR    │           │
│   └───────┬────────┘    └───────┬────────┘    └───────┬────────┘           │
│           │                      │                      │                    │
│   ┌───────┴───────┐    ┌────────┴────────┐    ┌───────┴───────┐           │
│   │               │    │                 │    │               │           │
│   ▼               ▼    ▼                 ▼    ▼               ▼           │
│ ┌─────────┐  ┌─────────┐  ┌─────────────┐ ┌─────────┐  ┌─────────┐       │
│ │SOC Mgr  │  │ Lead    │  │ DevOps/Sec  │ │ Sales   │  │ Marketing│      │
│ │         │  │ Engineer│  │ Engineer    │ │ Manager │  │ Manager │       │
│ └────┬────┘  └────┬────┘  └──────┬──────┘ └─────────┘  └─────────┘       │
│      │            │              │                                          │
│ ┌────┴────┐  ┌────┴────┐  ┌─────┴─────┐                                   │
│ │ 2x SOC │  │ 2x      │  │ 2x        │                                   │
│ │Analysts│  │DevOps   │  │ Security  │                                   │
│ │(24/7)  │  │ Engineers│  │ Engineers │                                   │
│ └─────────┘  └─────────┘  └───────────┘                                   │
│                                                                              │
│ TOTAL: 15-20 personnes                                                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

# 9. ESTIMATION BUDGÉTAIRE

## 9.1 Investissement Initial (24 mois)

| Catégorie                  | Description                     | Coût (€)      |
| -------------------------- | ------------------------------- | ------------- |
| **Infrastructure**         |                                 | **350,000**   |
| - Serveurs (On-premise)    | 6x Dell PowerEdge               | 120,000       |
| - Stockage (NAS/SAN)       | 50TB                            | 50,000        |
| - Équipement réseau        | Switch, Firewall, Load Balancer | 80,000        |
| - Cloud (AWS backup)       | 24 mois                         | 100,000       |
| **Licences & Abonnements** |                                 | **180,000**   |
| - SIEM (Elastic)           | Enterprise (log retention)      | 72,000        |
| - Threat Intel feeds       | Multi-sources                   | 36,000        |
| - Certificats & outils     | Misc                            | 12,000        |
| - Formation certifications | CISSP, CEH, OSCP                | 60,000        |
| **Personnel (24 mois)**    |                                 | **960,000**   |
| - Salaires (15 personnes)  | Moyenne 40k€                    | 960,000       |
| **Développement**          |                                 | **200,000**   |
| - Plateforme custom        | Development                     | 150,000       |
| - Intégrations             | 3rd party                       | 50,000        |
| **Marketing & Commercial** |                                 | **100,000**   |
| **Contingence (10%)**      |                                 | **179,000**   |
| **TOTAL**                  |                                 | **1,969,000** |

## 9.2 Coûts Récurrents (Annuel)

| Catégorie                        | Coût (€/an) |
| -------------------------------- | ----------- |
| Infrastructure (cloud + on-prem) | 120,000     |
| Licences & Abonnements           | 90,000      |
| Personnel (15 personnes)         | 600,000     |
| Marketing & Commercial           | 80,000      |
| **TOTAL**                        | **890,000** |

## 9.3 Modèle de Revenus

| Service                  | Prix (€/mois)      | Marges |
| ------------------------ | ------------------ | ------ |
| SOC 24/7 (Enterprise)    | 15,000-50,000      | 40%    |
| SOC 8/5 (PME)            | 3,000-8,000        | 35%    |
| Managed Detection        | 1,000-3,000        | 45%    |
| Pentest-as-a-Service     | 5,000-15,000/test  | 50%    |
| Threat Intelligence Feed | 500-2,000          | 60%    |
| Formation                | 1,000-5,000/cursus | 70%    |

---

# 10. RISQUES & MITIGATION

| Risque                      | Probabilité | Impact   | Mitigation                     |
| --------------------------- | ----------- | -------- | ------------------------------ |
| Manque de talents qualifiés | Haute       | Élevé    | Programme de formation interne |
| Concurrence internationale  | Moyenne     | Moyen    | Différenciation locale, prix   |
| Problèmes d'infrastructure  | Moyenne     | Élevé    | Redondance, backup cloud       |
| Réglementation              | Basse       | Moyen    | Compliance dès le départ       |
| Cyberattaques               | Haute       | Critique | SOC auto-protégé               |
| Financement                 | Moyenne     | Élevé    | Diversification clients        |

---

# ANNEXES

## A. Glossaire

| Terme        | Définition                                      |
| ------------ | ----------------------------------------------- |
| APT          | Advanced Persistent Threat                      |
| CVE          | Common Vulnerabilities and Exposures            |
| EDR          | Endpoint Detection and Response                 |
| IOC          | Indicator of Compromise                         |
| IDS/IPS      | Intrusion Detection/Prevention System           |
| MISP         | Malware Information Sharing Platform            |
| MITRE ATT&CK | Adversarial Tactics, Techniques, and Procedures |
| SIEM         | Security Information and Event Management       |
| SOC          | Security Operations Center                      |
| SOAR         | Security Orchestration, Automation and Response |
| TI           | Threat Intelligence                             |
| WAF          | Web Application Firewall                        |

---

_Document généré par AFRI SECURE SHIELD_
_Version 1.0 - Janvier 2026_
