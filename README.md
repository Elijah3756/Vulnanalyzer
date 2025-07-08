# Vulnerability Analyzer

A **containerized** CLI tool for analyzing vulnerability data using CVE, PURL, CPE identifiers, or performing comprehensive wildcard searches. This tool provides vulnerability introduction rates and historical usage rates by analyzing the extensive CVE database.

## Quick Start

Get started in 3 simple steps:

```bash
# 1. Build the container
make docker-build

# 2. Set up data and database  
make setup

# 3. Analyze vulnerabilities
make analyze-cve          # Analyze Log4Shell
make analyze-wildcard     # Search Python ecosystem
```

## Features

- **Containerized**: Run from any machine with Docker - no local dependencies needed
- **Multi-format Support**: Analyze CVE IDs, Package URLs (PURL), or Common Platform Enumeration (CPE)
- **Wildcard Search**: Comprehensive analysis of any technology, language, or product (e.g., "python", "apache *", "nodejs")
- **Component Analysis**: Break down PURL and CPE components for detailed risk assessment
- **Lightning Fast**: SQLite database for 200-500x faster queries than file-based analysis
- **Enhanced Risk Metrics**: Calculate vulnerability activity rates, exploitation risks, and threat levels
- **Smart Recommendations**: Actionable insights based on component analysis
- **Single Container**: Simple Docker setup with all functionality in one image

## Container Installation & Setup

### Prerequisites
- Docker (20.10+)

### Build & Initialize

```bash
# Build the container image
make docker-build

# Complete setup (downloads KEV data, recent CVEs, builds database)
make setup

# Or do individual steps:
make download-kev        # Download CISA Known Exploited Vulnerabilities
make download-recent     # Download recent CVEs (30 days)
make create-database     # Build SQLite database
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
make create-database    # Build database from CVE files
make db-stats           # Show statistics
make db-rebuild         # Clear and rebuild
make db-query           # Interactive queries

# Direct database queries
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest query-database stats
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest query-database vendor "Microsoft" --limit 20
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest query-database search "buffer overflow"
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

### Development Setup

```bash
# Interactive development shell
make docker-shell

# Build and test locally
make install-local
make test-local
make lint-local
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

### Single Container Design

The vulnerability analyzer runs as a single Docker container that can perform multiple functions:

- **Main Analysis**: CVE, PURL, CPE vulnerability analysis
- **Data Download**: CVE data from NVD API and CISA KEV catalog
- **Database Management**: SQLite database creation and queries
- **Interactive Shell**: Development and debugging capabilities

### Volume Structure

```
/app/data/
├── cvelistV5/cves/           # CVE JSON files
├── databases/                # SQLite databases
├── downloads/                # Downloaded data
└── known_exploited_vulnerabilities.json
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

### Single Container Deployment

```bash
# Build for production
make docker-build

# Complete setup
make setup

# Run specific analysis
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest CVE-2021-44228
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
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest create-database --clear
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest query-database stats

# Data downloads with API key
docker run --rm -v vuln_data:/app/data \
  -e NVD_API_KEY=your_key_here vuln-analyzer:latest download-cves --recent-days 7

# Interactive database queries
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest query-database vendor "Apache" --limit 10
```

## 🔄 Container Management

### Common Operations

```bash
# Full system reset
make reset

# Update and rebuild
make docker-clean
make docker-build
make setup

# View running containers
docker ps

# Stop any running containers
docker stop $(docker ps -q --filter ancestor=vuln-analyzer:latest)
```

### Troubleshooting

```bash
# Check container logs (if running detached)
docker logs <container_id>

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
docker build -t vuln-analyzer:ci .
docker run --rm vuln-analyzer:ci health

# Deploy to production
docker tag vuln-analyzer:ci vuln-analyzer:latest
# Container is now ready for deployment
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

1. **Container won't start**: Check Docker version and available disk space
2. **Data not persisting**: Verify volume mounts are working (`docker volume inspect vuln_data`)
3. **Slow downloads**: Get an NVD API key, increase retry settings
4. **Database errors**: Rebuild database with `make db-rebuild`

### Getting Help

```bash
# Container help
docker run --rm vuln-analyzer:latest --help

# Make command help
make help

# Check container status
docker ps
docker logs <container_id>
```

### Performance Optimization

```bash
# Run container with increased resources
docker run --rm -v vuln_data:/app/data --memory=4g --cpus=2 vuln-analyzer:latest

# Optimize database
make db-rebuild

# Use API key for downloads
docker run --rm -v vuln_data:/app/data -e NVD_API_KEY=your_key vuln-analyzer:latest download-cves --recent-days 30
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Contributing

Contributions are welcome! The containerized setup makes development easy:

```bash
# Start development shell
make docker-shell

# Make changes, test locally
make install-local
make test-local

# Submit PR
```

## Acknowledgments

- CVE Project for providing vulnerability data
- NVD API for real-time vulnerability feeds  
- CISA for Known Exploited Vulnerabilities catalog
- Docker community for containerization best practices 