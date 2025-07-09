.PHONY: help build run test clean install lint format docker-build docker-run

help:
	@echo "Vulnerability Analyzer - Containerized Commands"
	@echo ""
	@echo "Docker Operations:"
	@echo "  docker-build         - Build Docker image"
	@echo "  docker-run           - Run container with help"
	@echo "  docker-shell         - Start interactive shell in container"
	@echo "  docker-clean         - Clean Docker images and containers"
	@echo ""
	@echo "Setup Commands:"
	@echo "  setup                - Complete setup (download + build database)"
	@echo "  download-kev         - Download CISA Known Exploited Vulnerabilities"
	@echo "  download-recent      - Download recent CVEs (30 days)"
	@echo "  download-year        - Download CVEs for 2024"
	@echo "  download-all         - Download ALL CVEs (with retry protection)"
	@echo "  create-database      - Create database from CVE files"
	@echo ""
	@echo "Analysis Examples:"
	@echo "  analyze-cve          - Analyze CVE-2021-44228 (Log4Shell)"
	@echo "  analyze-purl         - Analyze npm package (lodash)"
	@echo "  analyze-wildcard     - Analyze Python ecosystem"
	@echo "  analyze-comprehensive - Comprehensive Apache analysis"
	@echo ""
	@echo "Database Operations:"
	@echo "  db-stats             - Show database statistics"
	@echo "  db-query             - Interactive database queries"
	@echo ""
	@echo "Development:"
	@echo "  install-local        - Install locally with uv (non-Docker)"
	@echo "  test-local           - Run tests locally"
	@echo "  lint-local           - Run linting locally"
	@echo ""
	@echo "Quick Start:"
	@echo "  quick-start          - Complete setup from scratch"
	@echo "  demo                 - Run demo analysis"
	@echo ""
	@echo "Examples:"
	@echo "  make setup               # Download data and build database"
	@echo "  make analyze-cve         # Analyze Log4Shell vulnerability"
	@echo "  make download-recent     # Get latest 30 days of CVEs"

# ================================================
# Docker Operations
# ================================================

docker-build:
	@echo "Building Docker image..."
	docker build -t vuln-analyzer:latest .

docker-run:
	@echo "Running vulnerability analyzer container..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest --help

docker-shell:
	@echo "Starting interactive shell..."
	docker run --rm -it -v vuln_data:/app/data vuln-analyzer:latest shell

docker-clean:
	@echo "Cleaning Docker resources..."
	docker image prune -f
	docker container prune -f
	-docker rmi vuln-analyzer:latest

# ================================================
# Setup and Data Management
# ================================================

setup: download-kev download-recent create-database
	@echo "Complete setup finished!"

download-kev:
	@echo "Downloading CISA Known Exploited Vulnerabilities..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest download-kev

download-recent:
	@echo "Downloading recent CVEs (30 days)..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest download-cves --recent-days 30

download-year:
	@echo "Downloading CVEs for 2024..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest download-cves --year 2024

download-all:
	@echo "Downloading ALL CVEs (this will take a while)..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest download-cves --all --max-retries 10 --retry-delay 180

create-database:
	@echo "Creating vulnerability database..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest create-database

# ================================================
# Database Operations
# ================================================

db-stats:
	@echo "Showing database statistics..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest query-database stats

db-query:
	@echo "Starting interactive database queries..."
	docker run --rm -it -v vuln_data:/app/data vuln-analyzer:latest query-database --help

db-rebuild:
	@echo "Rebuilding database..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest create-database --clear

# ================================================
# Analysis Examples
# ================================================

analyze-cve:
	@echo "Analyzing CVE-2021-44228 (Log4Shell)..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest cve CVE-2021-44228

analyze-purl:
	@echo "Analyzing npm package (lodash)..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest purl "pkg:npm/lodash@4.17.20"

analyze-wildcard:
	@echo "Analyzing Python ecosystem..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest wildcard "python"

analyze-comprehensive:
	@echo "Comprehensive Apache analysis..."
	docker run --rm -v vuln_data:/app/data vuln-analyzer:latest wildcard "apache *" --comprehensive

# ================================================
# Development
# ================================================

install-local:
	@echo "Installing locally with uv..."
	uv pip install -e .

install-dev-local:
	@echo "Installing with dev dependencies..."
	uv pip install -e ".[dev]"

test-local:
	@echo "Running tests locally..."
	pytest

lint-local:
	@echo "Running linting locally..."
	flake8 src/vulnanalyzer/
	mypy src/vulnanalyzer/

format-local:
	@echo "Formatting code locally..."
	black src/vulnanalyzer/

clean-local:
	@echo "Cleaning local artifacts..."
	rm -rf build/ dist/ *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# ================================================
# Quick Start & Demo
# ================================================

quick-start: docker-build setup
	@echo ""
	@echo "Quick start completed!"
	@echo ""
	@echo "Try these commands:"
	@echo "  make analyze-cve          # Analyze a specific CVE"
	@echo "  make analyze-wildcard     # Search Python vulnerabilities"
	@echo "  make db-stats             # Show database statistics"
	@echo ""

demo: analyze-cve
	@echo ""
	@echo "Demo completed! Try more examples:"
	@echo "  make analyze-purl"
	@echo "  make analyze-wildcard"
	@echo "  make analyze-comprehensive"

# ================================================
# Utility Commands
# ================================================

reset:
	@echo "Resetting all data..."
	docker volume rm vuln_data || true
	$(MAKE) setup

# ================================================
# Legacy Compatibility
# ================================================

build: docker-build
run: docker-run
test: test-local
clean: docker-clean clean-local 