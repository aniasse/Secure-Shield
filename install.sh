#!/bin/bash

# Secure Shield - Installation Script
# Usage: ./install.sh [dev|prod]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_NAME="Secure Shield"
VERSION="1.0.0"
CONFIG_FILE=".env"

# Functions
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    print_status "Vérification des prérequis..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker n'est pas installé"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose n'est pas installé"
        exit 1
    fi
    
    # Check Git
    if ! command -v git &> /dev/null; then
        print_error "Git n'est pas installé"
        exit 1
    fi
    
    # Check Node.js
    if ! command -v node &> /dev/null; then
        print_warning "Node.js n'est pas installé. L'installation continuera mais le développement sera limité."
    fi
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        print_warning "Python 3 n'est pas installé. L'installation continuera mais les fonctionnalités ML/AI seront limitées."
    fi
    
    print_success "Tous les prérequis sont satisfaits!"
}

create_env_file() {
    print_status "Création du fichier de configuration..."
    
    if [ ! -f "$CONFIG_FILE" ]; then
        cat > "$CONFIG_FILE" << EOF
# Secure Shield Configuration
# Generated on $(date)

# Database
POSTGRES_DB=secure_shield
POSTGRES_USER=secure_shield
POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-secure_shield}

# Redis
REDIS_PASSWORD=${REDIS_PASSWORD:-secure_shield}

# JWT
JWT_SECRET=${JWT_SECRET:-${JWT_SECRET_DEV:-$(openssl rand -hex 32)}}
JWT_EXPIRES_IN=24h

# Elasticsearch
ES_JAVA_OPTS="-Xms2g -Xmx2g"

# Kafka
KAFKA_BROKER_ID=1
KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1
KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1
KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1
KAFKA_LOG_RETENTION_HOURS=168

# Grafana
GRAFANA_ADMIN_PASSWORD=${GRAFANA_PASSWORD:-admin}

# Monitoring
PROMETHEUS_RETENTION_TIME=30d

# Security
MAX_LOGIN_ATTEMPTS=5
LOGIN_BLOCK_TIME=300

# Development/Production
NODE_ENV=${NODE_ENV:-development}
EOF
        print_success "Fichier de configuration créé: $CONFIG_FILE"
    else
        print_warning "Le fichier $CONFIG_FILE existe déjà. Il ne sera pas écrasé."
    fi
}

setup_development() {
    print_status "Configuration du mode développement..."
    
    # Install Node.js dependencies
    if command -v node &> /dev/null; then
        print_status "Installation des dépendances Node.js..."
        npm install
        print_success "Dépendances Node.js installées"
    fi
    
    # Install Python dependencies
    if command -v python3 &> /dev/null; then
        print_status "Installation des dépendances Python..."
        python3 -m pip install -r requirements.txt
        print_success "Dépendances Python installées"
    fi
    
    # Create development docker-compose file
    cat > docker-compose.dev.yml << EOF
version: "3.8"

services:
  # Development services
  siem:
    build:
      context: ./packages/soc-core
      dockerfile: Dockerfile
      target: siem
    ports:
      - "8080:8080"
    environment:
      - PORT=8080
      - NODE_ENV=development
      - DEBUG=true
      - LOG_LEVEL=debug
    volumes:
      - ./packages/soc-core:/app
      - /app/node_modules
    command: npm run dev

  # Other services with development configurations...
  # (Add development-specific configurations here)

  # Development tools
  maildev:
    image: maildev/maildev:latest
    ports:
      - "1080:80"
      - "1025:25"
    environment:
      - MAILDEV_INCOMING_USER=admin
      - MAILDEV_INCOMING_PASS=admin

  # Code quality tools
  eslint:
    image: node:18-alpine
    volumes:
      - ./packages/soc-core:/app
    working_dir: /app
    command: npm run lint
EOF
    print_success "Configuration développement terminée"
}

setup_production() {
    print_status "Configuration du mode production..."
    
    # Create production docker-compose file
    cat > docker-compose.prod.yml << EOF
version: "3.8"

services:
  # Production services with optimizations
  siem:
    build:
      context: ./packages/soc-core
      dockerfile: Dockerfile
      target: siem
    deploy:
      replicas: 2
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
    environment:
      - NODE_ENV=production
      - LOG_LEVEL=warn
      - ENABLE_METRICS=true

  # Other production optimizations...
  # (Add production-specific configurations here)

  # Reverse proxy
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - siem
      - threat-intel
      - soar

  # SSL certificates (Let's Encrypt)
  certbot:
    image: certbot/certbot:latest
    volumes:
      - ./nginx/ssl:/etc/letsencrypt
      - ./nginx/www:/var/www/certbot
    command: certonly --webroot -w /var/www/certbot -d yourdomain.com --email admin@yourdomain.com --agree-tos --no-eff-email
EOF
    print_success "Configuration production terminée"
}

start_services() {
    local mode="$1"
    
    print_status "Démarrage des services en mode $mode..."
    
    if [ "$mode" = "dev" ]; then
        docker-compose -f docker-compose.dev.yml up -d
    elif [ "$mode" = "prod" ]; then
        docker-compose -f docker-compose.prod.yml up -d
    else
        docker-compose up -d
    fi
    
    print_status "Vérification des services..."
    sleep 10
    docker-compose ps
    
    print_success "Services démarrés avec succès!"
}

health_check() {
    print_status "Vérification de l'intégrité des services..."
    
    # Check Elasticsearch
    if ! curl -f http://localhost:9200/_cluster/health?pretty > /dev/null 2>&1; then
        print_warning "Elasticsearch n'est pas accessible"
    fi
    
    # Check Redis
    if ! redis-cli -h localhost ping > /dev/null 2>&1; then
        print_warning "Redis n'est pas accessible"
    fi
    
    # Check services
    local services=("8080" "8081" "8082" "5601" "3000" "9090")
    for port in "${services[@]}"; do
        if ! nc -z localhost "$port" > /dev/null 2>&1; then
            print_warning "Service sur le port $port n'est pas accessible"
        fi
    done
    
    print_success "Vérification de santé terminée"
}

cleanup() {
    print_status "Nettoyage des ressources..."
    
    # Stop all containers
    docker-compose down
    
    # Remove unused images and volumes
    docker system prune -f
    docker volume prune -f
    
    print_success "Nettoyage terminé"
}

show_help() {
    echo "Usage: $0 [OPTION]..."
    echo ""
    echo "Options:"
    echo "  dev          Configuration et démarrage en mode développement"
    echo "  prod         Configuration et démarrage en mode production"
    echo "  install      Installation des dépendances"
    echo "  start        Démarrage des services"
    echo "  stop         Arrêt des services"
    echo "  restart      Redémarrage des services"
    echo "  status       Statut des services"
    echo "  health       Vérification de santé"
    echo "  logs         Affichage des logs"
    echo "  cleanup      Nettoyage des ressources"
    echo "  help         Affiche cette aide"
    echo ""
    echo "Exemples:"
    echo "  $0 dev        # Configuration développement"
    echo "  $0 start      # Démarrage des services"
    echo "  $0 health     # Vérification santé"
}

# Main script
case "${1:-help}" in
    dev)
        check_requirements
        create_env_file
        setup_development
        start_services "dev"
        health_check
        ;;
    prod)
        check_requirements
        create_env_file
        setup_production
        start_services "prod"
        health_check
        ;;
    install)
        check_requirements
        create_env_file
        if command -v node &> /dev/null; then
            npm install
        fi
        if command -v python3 &> /dev/null; then
            python3 -m pip install -r requirements.txt
        fi
        print_success "Installation des dépendances terminée"
        ;;
    start)
        start_services "default"
        ;;
    stop)
        print_status "Arrêt des services..."
        docker-compose down
        print_success "Services arrêtés"
        ;;
    restart)
        print_status "Redémarrage des services..."
        docker-compose restart
        sleep 10
        health_check
        ;;
    status)
        docker-compose ps
        ;;
    health)
        health_check
        ;;
    logs)
        docker-compose logs -f
        ;;
    cleanup)
        cleanup
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Option inconnue: $1"
        show_help
        exit 1
        ;;
esac