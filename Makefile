.PHONY: help build run test clean install lint format docker-build docker-run

help:
	@echo "🔍 Vulnerability Analyzer - Containerized Commands"
	@echo ""
	@echo "🐳 Docker Operations:"
	@echo "  docker-build         - Build Docker image (production)"
	@echo "  docker-build-dev     - Build Docker image (development)"
	@echo "  docker-run           - Run container with help"
	@echo "  docker-shell         - Start interactive shell in container"
	@echo "  docker-init          - Initialize container environment"
	@echo "  docker-clean         - Clean Docker images and containers"
	@echo ""
	@echo "📦 Container Management:"
	@echo "  container-up         - Start all services"
	@echo "  container-down       - Stop all services"
	@echo "  container-logs       - Show container logs"
	@echo "  container-setup      - Complete setup (download + build database)"
	@echo "  container-reset      - Reset all data and rebuild"
	@echo ""
	@echo "📊 Database Operations (Containerized):"
	@echo "  db-create            - Create database from CVE files"
	@echo "  db-stats             - Show database statistics"
	@echo "  db-query             - Interactive database queries"
	@echo "  db-rebuild           - Clear and rebuild database"
	@echo ""
	@echo "📥 CVE Data Management (Containerized):"
	@echo "  download-recent      - Download recent CVEs (30 days)"
	@echo "  download-year        - Download CVEs for 2024"
	@echo "  download-all         - Download ALL CVEs (with retry protection)"
	@echo "  download-kev         - Download CISA Known Exploited Vulnerabilities"
	@echo ""
	@echo "🔍 Analysis Examples (Containerized):"
	@echo "  analyze-cve          - Analyze CVE-2021-44228 (Log4Shell)"
	@echo "  analyze-purl         - Analyze npm package (lodash)"
	@echo "  analyze-wildcard     - Analyze Python ecosystem"
	@echo "  analyze-comprehensive - Comprehensive Apache analysis"
	@echo ""
	@echo "🛠 Development:"
	@echo "  dev-up               - Start development environment"
	@echo "  dev-shell            - Development shell with code mount"
	@echo "  install-local        - Install locally with uv (non-Docker)"
	@echo "  test-local           - Run tests locally"
	@echo "  lint-local           - Run linting locally"
	@echo ""
	@echo "📋 Quick Start:"
	@echo "  quick-start          - Complete setup from scratch"
	@echo "  demo                 - Run demo analysis"
	@echo ""
	@echo "💡 Examples:"
	@echo "  make container-setup     # Download data and build database"
	@echo "  make analyze-cve         # Analyze Log4Shell vulnerability"
	@echo "  make download-recent     # Get latest 30 days of CVEs"
	@echo "  make dev-up              # Start development environment"

# ================================================
# Docker Operations
# ================================================

docker-build:
	@echo "🐳 Building production Docker image..."
	docker build -t vuln-analyzer:latest --target production .

docker-build-dev:
	@echo "🐳 Building development Docker image..."
	docker build -t vuln-analyzer:dev --target development .

docker-run:
	@echo "🐳 Running vulnerability analyzer container..."
	docker run --rm vuln-analyzer:latest

docker-shell:
	@echo "🐳 Starting interactive shell..."
	docker run --rm -it vuln-analyzer:latest shell

docker-init:
	@echo "🐳 Initializing container environment..."
	docker run --rm vuln-analyzer:latest init

docker-clean:
	@echo "🐳 Cleaning Docker resources..."
	docker image prune -f
	docker container prune -f
	-docker rmi vuln-analyzer:latest vuln-analyzer:dev

# ================================================
# Container Management with Docker Compose
# ================================================

container-up:
	@echo "📦 Starting all services..."
	docker-compose up -d vuln-analyzer

container-down:
	@echo "📦 Stopping all services..."
	docker-compose down

container-logs:
	@echo "📦 Showing container logs..."
	docker-compose logs -f

container-setup: download-kev download-recent db-create
	@echo "📦 Complete container setup finished!"

container-reset:
	@echo "📦 Resetting all data..."
	docker-compose down -v
	docker volume prune -f
	$(MAKE) container-setup

# ================================================
# Database Operations (Containerized)
# ================================================

db-create:
	@echo "📊 Creating vulnerability database..."
	docker-compose --profile setup run --rm database-builder

db-stats:
	@echo "📊 Showing database statistics..."
	docker-compose --profile query run --rm query-service stats

db-query:
	@echo "📊 Starting interactive database queries..."
	docker-compose --profile query run --rm query-service --help

db-rebuild:
	@echo "📊 Rebuilding database..."
	docker-compose --profile setup run --rm database-builder --clear

# ================================================
# CVE Data Management (Containerized)
# ================================================

download-recent:
	@echo "📥 Downloading recent CVEs (30 days)..."
	docker-compose --profile download run --rm cve-downloader --recent-days 30

download-year:
	@echo "📥 Downloading CVEs for 2024..."
	docker-compose --profile download run --rm cve-downloader --year 2024

download-all:
	@echo "📥 Downloading ALL CVEs (this will take a while)..."
	docker-compose --profile download run --rm cve-downloader --all --max-retries 10 --retry-delay 180

download-kev:
	@echo "📥 Downloading CISA Known Exploited Vulnerabilities..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest download-kev

# ================================================
# Analysis Examples (Containerized)
# ================================================

analyze-cve:
	@echo "🔍 Analyzing CVE-2021-44228 (Log4Shell)..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest CVE-2021-44228 --output-format pretty

analyze-purl:
	@echo "🔍 Analyzing npm package (lodash)..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest "pkg:npm/lodash@4.17.20" --output-format pretty

analyze-wildcard:
	@echo "🔍 Analyzing Python ecosystem..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest python --output-format pretty

analyze-comprehensive:
	@echo "🔍 Comprehensive Apache analysis..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest --comprehensive "apache *" --output-format pretty

# ================================================
# Development
# ================================================

dev-up:
	@echo "🛠 Starting development environment..."
	docker-compose --profile dev up -d vuln-analyzer-dev

dev-shell:
	@echo "🛠 Starting development shell..."
	docker-compose --profile dev run --rm vuln-analyzer-dev shell

install-local:
	@echo "🛠 Installing locally with uv..."
	uv pip install -e .

install-dev-local:
	@echo "🛠 Installing with dev dependencies..."
	uv pip install -e ".[dev]"

test-local:
	@echo "🛠 Running tests locally..."
	pytest

lint-local:
	@echo "🛠 Running linting locally..."
	flake8 vuln_analyzer/
	mypy vuln_analyzer/

format-local:
	@echo "🛠 Formatting code locally..."
	black vuln_analyzer/

clean-local:
	@echo "🛠 Cleaning local artifacts..."
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# ================================================
# Quick Start & Demo
# ================================================

quick-start: docker-build container-setup
	@echo ""
	@echo "🎉 Quick start completed!"
	@echo ""
	@echo "Try these commands:"
	@echo "  make analyze-cve          # Analyze a specific CVE"
	@echo "  make analyze-wildcard     # Search Python vulnerabilities"
	@echo "  make db-stats             # Show database statistics"
	@echo ""

demo: analyze-cve
	@echo ""
	@echo "🎬 Demo completed! Try more examples:"
	@echo "  make analyze-purl"
	@echo "  make analyze-wildcard"
	@echo "  make analyze-comprehensive"

# ================================================
# Legacy Compatibility (Docker-based)
# ================================================

build: docker-build
run: docker-run
test: test-local
clean: docker-clean clean-local 