# Vulnerability Analyzer

A containerized CLI tool for analyzing vulnerability data using CVE, PURL, CPE identifiers, or performing comprehensive wildcard searches. This tool provides vulnerability introduction rates and historical usage rates by analyzing the extensive CVE database.

## Features

- **Multi-format Support**: Analyze CVE IDs, Package URLs (PURL), or Common Platform Enumeration (CPE)
- **Wildcard Search**: Comprehensive analysis of any technology, language, or product (e.g., "python", "apache *", "nodejs")
- **Comprehensive Component Analysis**: Break down PURL and CPE components for detailed risk assessment
- **Enhanced Risk Metrics**: Calculate vulnerability activity rates, exploitation risks, and threat levels
- **Database System**: SQLite database for lightning-fast queries (200-500x faster than file-based)
- **Containerized**: Ready-to-use Docker container with all dependencies
- **Fast Performance**: Intelligent caching and optimized data processing
- **Flexible Output**: JSON or human-readable output formats
- **Security Recommendations**: Actionable insights based on component analysis

## Installation

### Using Docker (Recommended)

1. **Build the Docker image:**
   ```bash
   docker build -t vuln-analyzer .
   ```

2. **Run the container:**
   ```bash
   # Basic usage
   docker run --rm vuln-analyzer CVE-2020-0001
   
   # With custom CVE data path
   docker run --rm -v /path/to/cvelistV5:/app/cvelistV5 vuln-analyzer CVE-2020-0001
   ```

### Using uv (Local Development)

1. **Install uv:**
   ```bash
   pip install uv
   ```

2. **Install the package:**
   ```bash
   uv pip install .
   ```

3. **Run the tool:**
   ```bash
   vuln-analyzer CVE-2020-0001
   ```

## Usage

### Basic Commands

```bash
# Analyze a CVE ID
vuln-analyzer CVE-2020-0001

# Use database for faster queries (200-500x speedup)
vuln-analyzer CVE-2020-0001 --use-database cve_database.db

# Analyze a Package URL (PURL)
vuln-analyzer "pkg:npm/lodash@4.17.20"

# Analyze a CPE
vuln-analyzer "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"

# Specify input type explicitly
vuln-analyzer --input-type cve CVE-2020-0001

# Get verbose output
vuln-analyzer -v CVE-2020-0001

# Pretty format output
vuln-analyzer --output-format pretty CVE-2020-0001
```

### Comprehensive Component Analysis 🆕

Perform detailed component-by-component analysis for PURL and CPE identifiers:

```bash
# Comprehensive PURL analysis
vuln-analyzer --comprehensive "pkg:npm/express@4.17.1"

# Comprehensive CPE analysis  
vuln-analyzer --comprehensive "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

# With pretty output and verbose logging
vuln-analyzer -c --output-format pretty -v "pkg:maven/log4j/log4j@2.14.1"
```

### Wildcard Search Examples 🆕

Perform comprehensive analysis of any technology, language, or vendor:

```bash
# Analyze everything related to Python
vuln-analyzer python

# Analyze Apache products (explicit wildcard)
vuln-analyzer "apache *"

# Analyze Node.js ecosystem
vuln-analyzer nodejs

# Analyze Microsoft products
vuln-analyzer microsoft

# Analyze OpenSSL with comprehensive breakdown
vuln-analyzer --comprehensive openssl

# Database-powered wildcard search (faster)
vuln-analyzer python --use-database cve_database.db

# Pretty output for wildcard search
vuln-analyzer --output-format pretty "java *"
```

### Docker Examples

```bash
# Basic CVE analysis
docker run --rm vuln-analyzer CVE-2020-0001

# Comprehensive package analysis
docker run --rm vuln-analyzer -c "pkg:npm/express@4.17.1"

# CPE analysis with pretty output
docker run --rm vuln-analyzer --output-format pretty "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

# Mount custom CVE data directory
docker run --rm -v /path/to/cvelistV5:/app/cvelistV5 vuln-analyzer CVE-2020-0001
```

## Output Formats

### Standard Analysis Output

```json
{
  "identifier": "CVE-2020-0001",
  "input_type": "cve",
  "matched_cves": ["CVE-2020-0001", "CVE-2020-0002", "..."],
  "vulnerability_activity_rate": 2.30,
  "exploitation_risk": 0.152,
  "relative_threat_level": 0.0085,
  "analysis_period": "Year 2020",
  "total_cves_analyzed": 15420,
  "metadata": {
    "vendor": "google_android",
    "product": "Android",
    "published_date": "2020-01-08T18:25:12+00:00",
    "risk_summary": {
      "vulnerability_activity": {
        "rate": 2.30,
        "interpretation": "High - More active recently than historically"
      },
      "exploitation_risk": {
        "rate": 0.152,
        "interpretation": "High - 10-20% of vulnerabilities are exploited"
      }
    }
  }
}
```

### Comprehensive Analysis Output 🆕

```json
{
  "identifier": "pkg:npm/express@4.17.1",
  "input_type": "purl",
  "overall_analysis": { /* Standard analysis */ },
  "component_analyses": [
    {
      "component_name": "Package Type",
      "component_type": "package_type", 
      "component_value": "npm",
      "matched_cves": ["CVE-2021-1234", "..."],
      "vulnerability_activity_rate": 1.85,
      "exploitation_risk": 0.078,
      "relative_threat_level": 0.0032,
      "risk_level": "MEDIUM",
      "risk_summary": { /* Component risk details */ }
    },
    {
      "component_name": "Package Name",
      "component_type": "package_name",
      "component_value": "express", 
      "matched_cves": ["CVE-2021-5678", "..."],
      "vulnerability_activity_rate": 3.12,
      "exploitation_risk": 0.124,
      "relative_threat_level": 0.0089,
      "risk_level": "HIGH"
    }
  ],
  "aggregated_metrics": {
    "total_unique_cves": 150,
    "average_exploitation_risk": 0.089,
    "highest_risk_component_name": "Package Name",
    "most_active_component_name": "Package Name"
  },
  "recommendations": [
    "HIGH PRIORITY: Package Name (express) shows high recent vulnerability activity",
    "Consider upgrading from version 4.17.1 - current version has 5.2% exploitation risk",
    "MEDIUM: This package has notable exploitation risk - plan security review"
  ]
}
```

### Pretty Output Format

```
Comprehensive Analysis Results for pkg:npm/express@4.17.1
======================================================================
Input Type: PURL
Components Analyzed: 3

Overall Analysis:
  Total Matched CVEs: 127
  Overall Activity Rate: 2.45
  Overall Exploitation Risk: 8.90%
  Overall Threat Level: 0.067%

Component-by-Component Analysis:
--------------------------------------------------

1. Package Type: npm
   Risk Level: LOW
   Matched CVEs: 45
   Exploitation Risk: 3.20%
   Activity Rate: 1.85
   Top CVEs: CVE-2021-1234, CVE-2021-5678, ...

2. Package Name: express  
   Risk Level: HIGH
   Matched CVEs: 89
   Exploitation Risk: 12.40%
   Activity Rate: 3.12
   Top CVEs: CVE-2021-9999, CVE-2022-1111, ...

Security Recommendations:
========================================
1. HIGH PRIORITY: Package Name (express) shows high recent vulnerability activity
2. Consider upgrading from version 4.17.1 - current version has 5.2% exploitation risk  
3. MEDIUM: This package has notable exploitation risk - plan security review
```

### Wildcard Search Output 🆕

```
Comprehensive Wildcard Analysis Results for 'python'
================================================================================
Search Term: python
Total Matched CVEs: 1,247
Categories Found: 4

Overall Analysis:
  Recent CVEs (2020-2025): 542
  Historical CVEs (pre-2020): 705
  Known Exploited CVEs: 18
  Vulnerability Activity Rate: 1.54
  Exploitation Risk: 1.44%
  Database Coverage: 0.41%

Temporal Analysis:
  Trend: INCREASING
  Recent 5 Years: 542 CVEs
  Previous 5 Years: 298 CVEs
  Peak Year: 2023 (156 CVEs)

Category Breakdown:
------------------------------------------------------------

1. VENDORS
   Total CVEs: 423
   Unique Matches: 15
   Activity Rate: 1.23
   Exploitation Risk: 2.13% (MEDIUM)
   Top Matches:
     • python_software_foundation: 289 CVEs
     • python: 78 CVEs
     • djangoproject: 45 CVEs

2. PRODUCTS  
   Total CVEs: 892
   Unique Matches: 42
   Activity Rate: 1.67
   Exploitation Risk: 1.79% (LOW)
   Top Matches:
     • python: 456 CVEs
     • django: 123 CVEs
     • pillow: 89 CVEs

Security Recommendations:
==================================================
1. MEDIUM: 'python' has moderate exploitation risk (1.44%) - monitor for updates
2. INCREASED ACTIVITY: 'python' has higher recent vulnerability activity than historical average
3. High-risk categories found: vendors
4.   - vendors: 'python_software_foundation' has 289 CVEs with 2.13% exploitation risk
5. SIGNIFICANT VOLUME: Found 1,247 CVEs related to 'python' - systematic review recommended

Sample CVEs (showing first 15 of 1,247):
  - CVE-2024-0450
  - CVE-2024-6923
  - CVE-2023-40217
  ...
```

## Enhanced Risk Metrics 🆕

### Vulnerability Activity Rate
- **Formula**: `(Recent CVEs per year) / (Historical CVEs per year)`
- **Meaning**: How much more active vulnerability discovery is recently vs historically
- **Example**: 2.5 means 2.5x more CVEs per year recently than historically

### Exploitation Risk  
- **Formula**: `(KEV matches for component) / (Total CVEs for component)`
- **Meaning**: What percentage of this component's vulnerabilities are actually exploited
- **Example**: 0.15 means 15% of this component's CVEs are known to be exploited

### Relative Threat Level
- **Formula**: `(KEV matches for component) / (Total KEV entries)`
- **Meaning**: How significant this component is in the overall threat landscape
- **Example**: 0.05 means this component represents 5% of all known exploited vulnerabilities

## Wildcard Search Features 🆕

### Comprehensive Category Analysis
- **Vendors**: Search across all vendor names for related organizations
- **Products**: Analyze all products and technologies containing the search term  
- **Descriptions**: Full-text search through vulnerability descriptions
- **Problem Types**: Search vulnerability classifications and CWE categories

### Temporal Analysis
- **Trend Detection**: Identify increasing, decreasing, or stable vulnerability patterns
- **Peak Analysis**: Find years with highest vulnerability counts
- **Historical Comparison**: Compare recent (2020-2025) vs historical (pre-2020) activity

### Risk Recommendations
- **Automated Risk Assessment**: Category-level and overall risk scoring
- **Actionable Insights**: Specific recommendations based on search results
- **Priority Ranking**: Risk-based prioritization of security actions
- **Volume Alerts**: Warnings for large vulnerability volumes requiring systematic review

## Comprehensive Component Analysis Features

### PURL Component Analysis
- **Package Type**: Analyze ecosystem-level risks (npm, maven, pypi, etc.)
- **Namespace**: Organization or scope-specific vulnerabilities
- **Package Name**: Core package vulnerability analysis
- **Version**: Specific version vulnerability assessment

### CPE Component Analysis
- **Vendor**: Vendor-specific vulnerability patterns
- **Product**: Product-line security assessment
- **Vendor+Product**: Combined risk analysis for specific vendor-product combinations
- **Version**: Version-specific vulnerability analysis

### Risk Recommendations
- **Automated Risk Assessment**: Component-level risk scoring
- **Actionable Insights**: Specific upgrade and security recommendations
- **Priority Ranking**: Risk-based prioritization of security actions
- **Trend Analysis**: Historical vulnerability activity patterns

## Supported Input Types

### CVE IDs
- Format: `CVE-YYYY-NNNN` (e.g., `CVE-2020-0001`)
- Analysis: Finds related vulnerabilities in the same vendor/product

### Package URLs (PURL)
- Format: `pkg:type/namespace/name@version` (e.g., `pkg:npm/lodash@4.17.20`)
- Analysis: Searches for vulnerabilities affecting the specific package
- **Comprehensive Mode**: Analyzes each component separately for detailed risk assessment

### Common Platform Enumeration (CPE)
- Format: `cpe:version:part:vendor:product:version:update:edition:language`
- Example: `cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*`
- Analysis: Finds vulnerabilities for the specified platform/software
- **Comprehensive Mode**: Breaks down vendor, product, and version components for granular analysis

### Wildcard Search 🆕
- Format: Single terms (`python`, `apache`, `nodejs`) or explicit wildcards (`python *`, `microsoft *`)
- Analysis: Comprehensive search across vendors, products, descriptions, and vulnerability types
- **Categories**: Analyzes vendors, products, descriptions, and problem types separately
- **Auto-detection**: Automatically detects wildcard patterns and single-term searches

## Configuration

### Environment Variables

- `CVE_DATA_PATH`: Path to CVE data directory (default: `./cvelistV5/cves`)
- `PYTHONPATH`: Python path for module imports

### Command Line Options

- `--input-type`: Specify input type (cve, purl, cpe)
- `--cve-data-path`: Path to CVE data directory
- `--use-database`: Use SQLite database for faster queries
- `--output-format`: Output format (json, pretty)
- `--comprehensive, -c`: Perform comprehensive component analysis (PURL/CPE only)
- `--verbose, -v`: Enable verbose output
- `--help`: Show help message

## Development

### Project Structure

```
vuln_analyzer/
├── __init__.py          # Package initialization
├── cli.py               # Command-line interface
├── data_processor.py    # Core data processing logic
└── models.py           # Data models and structures
```

### Running Tests

```bash
# Install development dependencies
uv pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=vuln_analyzer
```

### Code Quality

```bash
# Format code
black vuln_analyzer/

# Lint code
flake8 vuln_analyzer/

# Type checking
mypy vuln_analyzer/
```

## Database System

### Lightning-Fast Queries

Create an indexed SQLite database for dramatically faster analysis:

```bash
# Build comprehensive vulnerability database
make create-database

# Use database for instant queries
vuln-analyzer CVE-2020-0001 --use-database cve_database.db

# Interactive database queries
python scripts/query_database.py stats
python scripts/query_database.py vendor "Microsoft" --limit 20
python scripts/query_database.py search "buffer overflow"
```

### Performance Comparison

| Operation | File-based | Database | Speedup |
|-----------|------------|----------|---------|
| CVE lookup | ~5 seconds | ~0.01s | **500x** |
| Vendor search | ~45 seconds | ~0.1s | **450x** |
| Text search | ~120 seconds | ~0.5s | **240x** |

### Database Features

- **300,711 CVE records** from 1999-2025
- **1,378 known exploited vulnerabilities** from CISA
- Full-text search with SQLite FTS5
- Comprehensive indexing for fast filtering
- ~850MB database vs ~2.1GB raw files (60% smaller)

## CVE Data

This tool expects CVE data in the CVE Record Format (JSON) organized by year and CVE number ranges. The data structure should follow the official CVE List v5 format:

```
cvelistV5/
├── cves/
│   ├── 2020/
│   │   ├── 0xxx/
│   │   │   ├── CVE-2020-0001.json
│   │   │   └── ...
│   │   └── 1xxx/
│   └── 2021/
│       └── ...
└── README.md
```

### CVE Download System

Update your CVE database with the latest vulnerabilities from the official NVD API:

```bash
# Download recent CVEs (last 30 days)
make update-cves

# Download CVEs for a specific year
make update-cves-year

# Test download (last 1 day)
make update-cves-test

# Download with API key for higher rate limits
./scripts/update_cve_database.sh --recent --api-key YOUR_API_KEY
```

The system downloads fresh CVE data in the official Record Format 5.x and organizes files by year and CVE number ranges for efficient processing.

## Docker Compose

For easier deployment, use the provided Docker Compose configuration:

```yaml
version: '3.8'
services:
  vuln-analyzer:
    build: .
    volumes:
      - ./cvelistV5:/app/cvelistV5
    command: ["--help"]
```

Run with: `docker-compose run vuln-analyzer CVE-2020-0001`

## Performance Considerations

- **Caching**: The tool caches loaded CVE data to improve performance
- **Sampling**: For large datasets, the tool uses intelligent sampling to balance accuracy and speed
- **Memory Usage**: Memory usage scales with the number of CVEs analyzed
- **Disk I/O**: Consider using SSD storage for better performance with large CVE datasets

## Metrics Explanation

### Vulnerability Introduction Rate
The rate at which vulnerabilities are introduced relative to the total number of vulnerabilities in the analyzed dataset. This helps understand how frequently new vulnerabilities appear for a given component.

### History Usage Rate
The historical rate of exploit usage based on available references, problem types, and related vulnerability data. This indicates how actively exploited vulnerabilities are in the wild.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Support

For issues and questions:
- Open an issue on GitHub
- Check the documentation
- Review the CVE data format specification

## Acknowledgments

- CVE Project for providing the vulnerability data
- CVE Services API for data access
- Contributors and maintainers of the CVE ecosystem 