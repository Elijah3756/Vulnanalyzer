.PHONY: help build run test clean install lint format docker-build docker-run

help:
	@echo "Available commands:"
	@echo ""
	@echo "Development:"
	@echo "  install      - Install the package locally with uv"
	@echo "  build        - Build the Docker image"
	@echo "  run          - Run the tool locally"
	@echo "  test         - Run tests"
	@echo "  lint         - Run linting"
	@echo "  format       - Format code"
	@echo "  clean        - Clean build artifacts"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run Docker container"
	@echo ""
	@echo "CVE Data Management:"
	@echo "  update-cves     - Download recent CVEs (last 30 days)"
	@echo "  update-cves-year - Download CVEs for 2024"
	@echo "  update-cves-test - Test download (last 1 day)"
	@echo "  download-cves-help - Show CVE download options"
	@echo ""
	@echo "Database Management:"
	@echo "  create-database - Create SQLite database from CVE files"
	@echo "  database-stats  - Show database statistics"
	@echo "  create-database-clear - Rebuild database (clear existing)"
	@echo "  query-database  - Show database query options"
	@echo "  query-stats     - Show database statistics"
	@echo ""
	@echo "Examples:"
	@echo "  example-cve  - Analyze CVE-2020-0001"
	@echo "  example-purl - Analyze pkg:npm/lodash@4.17.20"
	@echo "  example-cpe  - Analyze CPE"
	@echo "  example-wildcard - Analyze everything related to Python"
	@echo "  example-wildcard-comprehensive - Comprehensive Apache analysis"
	@echo "  example-wildcard-pretty - Pretty output for Node.js analysis"

install:
	uv pip install -e .

install-dev:
	uv pip install -e ".[dev]"

build: docker-build

run:
	vuln-analyzer --help

test:
	pytest

lint:
	flake8 vuln_analyzer/
	mypy vuln_analyzer/

format:
	black vuln_analyzer/

docker-build:
	docker build -t vuln-analyzer .

docker-run:
	docker run --rm vuln-analyzer --help

docker-run-cve:
	docker run --rm vuln-analyzer CVE-2020-0001

docker-compose-up:
	docker-compose run vuln-analyzer --help

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Example usage commands
example-cve:
	vuln-analyzer CVE-2020-0001

example-purl:
	vuln-analyzer "pkg:npm/lodash@4.17.20"

example-cpe:
	vuln-analyzer "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"

example-wildcard:
	vuln-analyzer python

example-wildcard-comprehensive:
	vuln-analyzer --comprehensive "apache *"

example-wildcard-pretty:
	vuln-analyzer --output-format pretty nodejs

# Docker examples
docker-example-cve:
	docker run --rm vuln-analyzer CVE-2020-0001

docker-example-purl:
	docker run --rm vuln-analyzer "pkg:npm/express@4.17.1"

docker-example-cpe:
	docker run --rm vuln-analyzer --output-format pretty "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

# CVE Data Management
update-cves:
	./scripts/update_cve_database.sh --recent

update-cves-year:
	./scripts/update_cve_database.sh --year 2024

update-cves-test:
	./scripts/update_cve_database.sh --test

download-recent-cves:
	cd scripts && python download_cves.py --recent-days 30 --output-dir ../cvelistV5/cves

download-year-cves:
	cd scripts && python download_cves.py --year 2024 --output-dir ../cvelistV5/cves

download-cves-help:
	cd scripts && python download_cves.py --help

# Database Management
create-database:
	cd scripts && python create_database.py --verbose

create-database-clear:
	cd scripts && python create_database.py --clear --verbose

database-stats:
	cd scripts && python create_database.py --stats-only

create-database-help:
	cd scripts && python create_database.py --help

query-database:
	cd scripts && python query_database.py --help

query-stats:
	cd scripts && python query_database.py --db-path ../cve_database.db stats 