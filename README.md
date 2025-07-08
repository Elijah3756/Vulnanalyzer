# Vulnerability Analyzer

A **fully containerized** CLI tool for analyzing vulnerability data using CVE, PURL, CPE identifiers, or performing comprehensive wildcard searches. This tool provides vulnerability introduction rates and historical usage rates by analyzing the extensive CVE database.

## Quick Start (Containerized)

Get started in 3 simple steps:

```bash
# 1. Build the container
make docker-build

# 2. Set up data and database  
make container-setup

# 3. Analyze vulnerabilities
make analyze-cve          # Analyze Log4Shell
make analyze-wildcard     # Search Python ecosystem
```

## Features

- **Fully Containerized**: Run from any machine with Docker - no local dependencies needed
- **Multi-format Support**: Analyze CVE IDs, Package URLs (PURL), or Common Platform Enumeration (CPE)
- **Wildcard Search**: Comprehensive analysis of any technology, language, or product (e.g., "python", "apache *", "nodejs")
- **Component Analysis**: Break down PURL and CPE components for detailed risk assessment
- **Lightning Fast**: SQLite database for 200-500x faster queries than file-based analysis
- **Enhanced Risk Metrics**: Calculate vulnerability activity rates, exploitation risks, and threat levels
- **Smart Recommendations**: Actionable insights based on component analysis
- **Container Orchestration**: Complete Docker Compose setup with multiple services

## Container Installation & Setup

### Prerequisites
- Docker (20.10+)
- Docker Compose (2.0+)

### Build & Initialize

```bash
# Build the container image
make docker-build

# Complete setup (downloads KEV data, recent CVEs, builds database)
make container-setup

# Or do individual steps:
make download-kev        # Download CISA Known Exploited Vulnerabilities
make download-recent     # Download recent CVEs (30 days)
make db-create          # Build SQLite database
```

### Verify Installation

```bash
# Check container health
make docker-run

# View database stats
make db-stats

# Test analysis
make analyze-cve
```

## Container Usage

### Analysis Commands

```bash
# Analyze specific vulnerabilities
make analyze-cve                    # CVE-2021-44228 (Log4Shell)
make analyze-purl                   # npm lodash package
make analyze-wildcard               # Python ecosystem
make analyze-comprehensive          # Comprehensive Apache analysis

# Direct container usage
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest CVE-2021-44228
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest "pkg:npm/express@4.17.1" --comprehensive
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest python --output-format pretty
```

### Database Operations

```bash
# Database management
make db-create          # Build database from CVE files
make db-stats           # Show statistics
make db-rebuild         # Clear and rebuild
make db-query           # Interactive queries

# Direct database queries
docker-compose --profile query run --rm query-service stats
docker-compose --profile query run --rm query-service vendor "Microsoft" --limit 20
docker-compose --profile query run --rm query-service search "buffer overflow"
```

### Data Management

```bash
# Download CVE data
make download-recent    # Last 30 days (fast)
make download-year      # Specific year (2024)
make download-all       # ALL CVEs (takes hours, 2-4GB)
make download-kev       # CISA Known Exploited Vulnerabilities

# With API key for faster downloads (50x speed increase)
echo "NVD_API_KEY=your_key_here" >> .env
make download-recent
```

## Development Environment

### Start Development Container

```bash
# Start development environment with live code mounting
make dev-up

# Interactive development shell
make dev-shell

# View development logs
make container-logs
```

### Local Development (Non-Containerized)

```bash
# Install locally for development
make install-local
make install-dev-local

# Run tests and linting
make test-local
make lint-local
make format-local
```

## Container Architecture

### Services Overview

```yaml
# Production services
vuln-analyzer       # Main analysis service
database-builder    # Database creation service  
cve-downloader     # CVE data download service
query-service      # Database query service

# Development services  
vuln-analyzer-dev  # Development environment with code mounting
```

### Volume Structure

```
/app/data/
├── cvelistV5/cves/           # CVE JSON files
├── databases/                # SQLite databases
├── downloads/                # Downloaded data
└── known_exploited_vulnerabilities.json

/app/config/                  # Configuration files
/app/logs/                    # Application logs
```

### Environment Variables

Key container environment variables:

```bash
CVE_DATA_PATH=/app/data/cvelistV5/cves
DATABASE_PATH=/app/data/databases/cve_database.db
KEV_FILE_PATH=/app/data/known_exploited_vulnerabilities.json
DOWNLOAD_DIR=/app/data/downloads
NVD_API_KEY=your_api_key_here
LOG_LEVEL=INFO
```

## Configuration

### Environment Setup

```bash
# Copy environment template
cp env.example .env

# Edit configuration
vim .env
```

### Key Configuration Options

```bash
# API Configuration (highly recommended)
NVD_API_KEY=your_nvd_api_key_here

# Performance Tuning
SQLITE_CACHE_SIZE=10000        # 10MB cache
MAX_RETRIES=5                  # Download retries
RETRY_DELAY=120               # Base retry delay

# Container Behavior
LOG_LEVEL=INFO                # DEBUG, INFO, WARNING, ERROR
RESTART_POLICY=unless-stopped # Container restart policy
```

## Container Performance

### Speed Comparison

| Operation | File-based | Database | Container |
|-----------|------------|----------|-----------|
| CVE lookup | ~5 seconds | ~0.01s | ~0.02s |
| Vendor search | ~45 seconds | ~0.1s | ~0.15s |
| Wildcard search | ~120 seconds | ~0.5s | ~0.6s |

### Storage Requirements

- **Container Image**: ~500MB
- **Database**: ~850MB (300k+ CVEs)
- **Full CVE Data**: ~2.1GB
- **Total Setup**: ~3.5GB

## Production Deployment

### Docker Compose Production

```bash
# Production deployment
docker-compose up -d vuln-analyzer

# With multiple profiles
docker-compose --profile download --profile setup up -d

# Scale specific services
docker-compose up -d --scale cve-downloader=2
```

### Health Monitoring

```bash
# Container health checks
docker run --rm vuln-analyzer:latest health

# Service status
docker-compose ps

# View logs
docker-compose logs -f vuln-analyzer
```

### Data Persistence

```bash
# Backup data volume
docker run --rm -v vuln_data:/data -v $(pwd):/backup alpine tar czf /backup/vuln_data_backup.tar.gz -C /data .

# Restore data volume
docker run --rm -v vuln_data:/data -v $(pwd):/backup alpine tar xzf /backup/vuln_data_backup.tar.gz -C /data
```

## Usage Examples

### Container Analysis Examples

```bash
# Basic vulnerability analysis
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest CVE-2021-44228

# Package analysis with comprehensive breakdown
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest \
  --comprehensive "pkg:npm/express@4.17.1" --output-format pretty

# Wildcard ecosystem analysis
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest \
  python --output-format pretty

# Using database for fast queries
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest \
  CVE-2021-44228 --use-database /app/data/databases/cve_database.db
```

### Container Service Usage

```bash
# Database operations
docker-compose --profile setup run --rm database-builder --clear
docker-compose --profile query run --rm query-service stats

# Data downloads with API key
docker-compose --profile download run --rm \
  -e NVD_API_KEY=your_key_here cve-downloader --recent-days 7

# Interactive database queries
docker-compose --profile query run --rm query-service vendor "Apache" --limit 10
```

## 🔄 Container Management

### Common Operations

```bash
# Full system reset
make container-reset

# Update and rebuild
make docker-clean
make docker-build
make container-setup

# View all services
docker-compose ps

# Scale services
docker-compose up -d --scale cve-downloader=3

# Stop everything
make container-down
```

### Troubleshooting

```bash
# Check container logs
docker-compose logs vuln-analyzer

# Interactive debugging
make docker-shell

# Verify data volumes
docker volume inspect vuln_data

# Container health check
docker run --rm vuln-analyzer:latest health
```

## Complete Container Workflows

### Daily Operations Workflow

```bash
# Morning: Update with latest CVEs
make download-recent
make db-rebuild

# Analysis throughout the day
make analyze-cve
make analyze-wildcard
```

### Research Workflow

```bash
# Initial setup for research
make container-setup

# Comprehensive data download
make download-all    # Takes several hours

# Analysis and exploration
make analyze-comprehensive
make db-query
```

### CI/CD Integration

```bash
# Build and test in CI/CD
docker build -t vuln-analyzer:ci --target production .
docker run --rm vuln-analyzer:ci health

# Deploy to production
docker tag vuln-analyzer:ci vuln-analyzer:latest
docker-compose up -d
```

## Migration from Local Installation

If you have an existing local installation:

```bash
# 1. Backup existing data
cp -r cvelistV5/ data/
cp known_exploited_vulnerabilities.json data/
cp *.db data/databases/

# 2. Build container
make docker-build

# 3. Verify data migration
make db-stats
make analyze-cve

# 4. Remove local installation (optional)
make clean-local
```

## Support & Troubleshooting

### Common Issues

1. **Container won't start**: Check Docker version, ensure ports aren't in use
2. **Data not persisting**: Verify volume mounts in docker-compose.yml
3. **Slow downloads**: Get an NVD API key, increase retry settings
4. **Database errors**: Rebuild database with `make db-rebuild`

### Getting Help

```bash
# Container help
docker run --rm vuln-analyzer:latest --help

# Make command help
make help

# Check container status
docker-compose ps
docker-compose logs
```

### Performance Optimization

```bash
# Increase container resources
docker-compose up -d --memory=4g --cpus=2

# Optimize database
make db-rebuild

# Use API key for downloads
echo "NVD_API_KEY=your_key" >> .env
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! The containerized setup makes development easy:

```bash
# Start development environment
make dev-up

# Make changes, test
make test-local

# Submit PR
```

## Acknowledgments

- CVE Project for providing vulnerability data
- NVD API for real-time vulnerability feeds  
- CISA for Known Exploited Vulnerabilities catalog
- Docker community for containerization best practices 