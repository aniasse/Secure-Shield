# Secure Shield - Makefile

# Project name
PROJECT := secure-shield
VERSION := 1.0.0

# Colors
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

# Default target
.DEFAULT_GOAL := help

# Targets
.PHONY: help install dev prod start stop restart status logs clean test lint security

## help: Affiche l'aide
help:
	@echo "Secure Shield - Makefile"
	@echo ""
	@echo "Usage: make [TARGET]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## install: Installation des dépendances
install: ## Installation des dépendances
	@echo "$(BLUE)[INFO]$(NC) Installation des dépendances..."
	@if command -v node &> /dev/null; then \
		npm install; \
		echo "$(GREEN)[SUCCESS]$(NC) Dépendances Node.js installées"; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) Node.js non trouvé, saut de l'installation"; \
	fi
	@if command -v python3 &> /dev/null; then \
		python3 -m pip install -r requirements.txt; \
		echo "$(GREEN)[SUCCESS]$(NC) Dépendances Python installées"; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) Python 3 non trouvé, saut de l'installation"; \
	fi
	@echo "$(GREEN)[SUCCESS]$(NC) Installation terminée"

## dev: Configuration et démarrage en mode développement
dev: ## Configuration et démarrage en mode développement
	@echo "$(BLUE)[INFO]$(NC) Configuration développement..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN)[SUCCESS]$(NC) Fichier .env créé"; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) Le fichier .env existe déjà"; \
	fi
	@docker-compose -f docker-compose.dev.yml up -d
	@echo "$(GREEN)[SUCCESS]$(NC) Services développement démarrés"

## prod: Configuration et démarrage en mode production
prod: ## Configuration et démarrage en mode production
	@echo "$(BLUE)[INFO]$(NC) Configuration production..."
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN)[SUCCESS]$(NC) Fichier .env créé"; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) Le fichier .env existe déjà"; \
	fi
	@docker-compose -f docker-compose.prod.yml up -d
	@echo "$(GREEN)[SUCCESS]$(NC) Services production démarrés"

## start: Démarrage des services
start: ## Démarrage des services
	@echo "$(BLUE)[INFO]$(NC) Démarrage des services..."
	@docker-compose up -d
	@echo "$(GREEN)[SUCCESS]$(NC) Services démarrés"

## stop: Arrêt des services
stop: ## Arrêt des services
	@echo "$(BLUE)[INFO]$(NC) Arrêt des services..."
	@docker-compose down
	@echo "$(GREEN)[SUCCESS]$(NC) Services arrêtés"

## restart: Redémarrage des services
restart: ## Redémarrage des services
	@echo "$(BLUE)[INFO]$(NC) Redémarrage des services..."
	@docker-compose restart
	@echo "$(GREEN)[SUCCESS]$(NC) Services redémarrés"

## status: Statut des services
status: ## Statut des services
	@echo "$(BLUE)[INFO]$(NC) Statut des services..."
	@docker-compose ps

## logs: Affichage des logs
logs: ## Affichage des logs
	@echo "$(BLUE)[INFO]$(NC) Affichage des logs..."
	@docker-compose logs -f

## clean: Nettoyage des ressources
clean: ## Nettoyage des ressources
	@echo "$(BLUE)[INFO]$(NC) Nettoyage des ressources..."
	@docker-compose down -v
	@docker system prune -f
	@echo "$(GREEN)[SUCCESS]$(NC) Nettoyage terminé"

## test: Exécution des tests
test: ## Exécution des tests
	@echo "$(BLUE)[INFO]$(NC) Exécution des tests..."
	@if [ -f "packages/soc-core/package.json" ]; then \
		cd packages/soc-core && npm test; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) Tests non trouvés"; \
	fi

## lint: Analyse de qualité de code
lint: ## Analyse de qualité de code
	@echo "$(BLUE)[INFO]$(NC) Analyse de qualité de code..."
	@if [ -f "packages/soc-core/package.json" ]; then \
		cd packages/soc-core && npm run lint; \
	else \
		echo "$(YELLOW)[WARNING]$(NC) Lint non trouvé"; \
	fi

## security: Analyse de sécurité
security: ## Analyse de sécurité
	@echo "$(BLUE)[INFO]$(NC) Analyse de sécurité..."
	@if command -v npm &> /dev/null; then \
		npm audit; \
	fi
	@if [ -f "requirements.txt" ]; then \
		pip-audit --file requirements.txt; \
	fi