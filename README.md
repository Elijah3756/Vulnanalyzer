# `vulnanalyzer`

`Vulnanalyzer` is a professional vulnerability analysis tool for CVE, PURL, CPE, and wildcard searches that provides detailed risk assessments, vulnerability activity rates, and exploitation risk analysis for software components, platforms, and technologies.

## Getting Started

### Install

#### From PyPI (Recommended)

```bash
pip install vulnanalyzer
```

#### From Source

Clone down this repository and install from source. We recommend using [`uv`](https://docs.astral.sh/uv/) as your package manager.

```bash
git clone https://github.com/Elijah3756/vulnerabililizer.git
cd vulnerabililizer
uv pip install -e .
```

### Usage

Initial setup to download vulnerability data and create the database:

```bash
vulnanalyzer setup

# Or with API key for faster downloads
vulnanalyzer setup --api-key YOUR_NVD_API_KEY
```

Basic vulnerability analysis commands:

```bash
vulnanalyzer cve CVE-2021-44228
```

```bash
vulnanalyzer purl "pkg:npm/lodash@4.17.20"
```

```bash
vulnanalyzer cpe "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
```

```bash
vulnanalyzer wildcard "python"
```

Update the database with recent vulnerability data:

```bash
vulnanalyzer update --days 7
```

### Arguments

#### Setup Command

| CLI Argument           | Description | Default | Environment Variable |
| :---------------- | :------: | :----: | :-----: |
| `--api-key`      |   NVD API key for faster downloads   | None | `NVD_API_KEY` |
| `--verbose`, `-v`          |   Enable verbose output   | False | N/A |

#### Update Command

| CLI Argument           | Description | Default | Environment Variable |
| :---------------- | :------: | :----: | :-----: |
| `--days`      |   Number of days to look back for recent CVEs   | 30 | N/A |
| `--api-key`          |   NVD API key for faster downloads   | None | `NVD_API_KEY` |
| `--verbose`, `-v`          |   Enable verbose output   | False | N/A |

#### Analysis Commands (cve, purl, cpe, wildcard)

| CLI Argument           | Description | Default | Environment Variable |
| :---------------- | :------: | :----: | :-----: |
| `--comprehensive`      |   Perform comprehensive component analysis   | False | N/A |
| `--output-format`          |   Output format: text, json, both   | both | N/A |
| `--verbose`, `-v`          |   Enable verbose output   | False | N/A |

#### Global Environment Variables

| Environment Variable           | Description | Default |
| :---------------- | :------: | :----: |
| `VULNANALYZER_DATA`      |   Data directory path   | `~/.vulnanalyzer` |
| `CVE_DATA_PATH`          |   CVE JSON files directory   | `~/.vulnanalyzer/cvelistV5/cves` |
| `DATABASE_PATH`          |   SQLite database path   | `~/.vulnanalyzer/databases/cve_database.db` |
| `KEV_FILE_PATH`          |   Known exploited vulnerabilities file   | `~/.vulnanalyzer/known_exploited_vulnerabilities_catalog.json` |

### Container Usage

We provide a containerized image for ease of use through Docker and Make commands.

#### Using Make (Recommended)

```bash
# Complete setup from scratch
make quick-start

# Analyze specific vulnerabilities
make analyze-cve          # Analyze Log4Shell
make analyze-purl         # Analyze npm package
make analyze-wildcard     # Analyze Python ecosystem

# Database operations
make setup                # Download data and build database
make download-recent      # Get latest 30 days of CVEs
make db-stats            # Show database statistics
```

#### Direct Docker Usage

```bash
# Build the image
docker build -t vuln-analyzer:latest .

# Run analysis
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest cve CVE-2021-44228

# Setup database
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest create-database

# Download recent CVE data
docker run --rm -v vuln_data:/app/data vuln-analyzer:latest download-cves --recent-days 30

# Interactive shell
docker run --rm -it -v vuln_data:/app/data vuln-analyzer:latest shell
```

## Testing Suite

The project includes a comprehensive test suite covering:

- **CLI Command Testing** - Validates all command-line interfaces
- **Analysis Engine Testing** - Tests CVE, PURL, CPE, and wildcard analysis
- **Database Integration Testing** - Verifies SQLite database operations
- **API Integration Testing** - Tests NVD API downloads and KEV data processing

Run tests locally:

```bash
# Install test dependencies
uv pip install -e ".[dev]"

# Run test suite
pytest

# Run with coverage
pytest --cov=vulnanalyzer --cov-report=html
```

## CVE Analysis Details

CVE analysis provides comprehensive vulnerability assessment for specific CVE identifiers:

- **Risk Metrics**: Vulnerability activity rate, exploitation risk, relative threat level
- **Related Vulnerabilities**: Finds CVEs affecting the same vendor/product
- **Temporal Analysis**: Recent vs historical vulnerability patterns
- **KEV Integration**: Identifies known exploited vulnerabilities
- **Vendor/Product Context**: Extracts affected vendors and products

**Example Output:**
```
VULNERABILITY ANALYSIS RESULTS
Identifier: CVE-2021-44228
Type: CVE
Total CVEs Analyzed: 25,432
Matched CVEs: 15

RISK METRICS
Vulnerability Activity Rate: 2.10 (High - More active recently)
Exploitation Risk: 18.50% (High - 10-20% of vulnerabilities exploited)
Relative Threat Level: 0.003% (Low - 0.2-1% of known exploited vulnerabilities)
```

## PURL and CPE Analysis Details

Package URL (PURL) and Common Platform Enumeration (CPE) analysis provides component-level security assessment:

### PURL Analysis
- **Package Ecosystem Analysis**: Evaluates npm, Maven, PyPI, and other package types
- **Component Breakdown**: Separate analysis of package type, namespace, name, and version
- **Version-Specific Risks**: Identifies vulnerabilities in specific package versions
- **Comprehensive Mode**: Detailed component-by-component risk assessment

### CPE Analysis
- **Platform Security Assessment**: Analyzes operating systems, applications, and hardware
- **Vendor Risk Profiles**: Evaluates security track record of specific vendors
- **Product Vulnerability Patterns**: Identifies vulnerability trends for specific products
- **Version Impact Analysis**: Assesses risks for specific software versions

**Example Comprehensive Analysis:**
```
Component Breakdown:
  Package Type (npm):
    Risk Level: MEDIUM
    CVEs Found: 1,250
    Exploitation Risk: 8.40%
    Activity Rate: 1.85

  Package Name (express):
    Risk Level: HIGH  
    CVEs Found: 28
    Exploitation Risk: 14.29%
    Activity Rate: 2.10

Top Recommendations:
  1. HIGH PRIORITY: 1 component(s) have high exploitation risk (>10%)
  2. Package 'express' shows high recent vulnerability activity - monitor for updates
  3. MEDIUM: This package has notable exploitation risk - plan security review
```

## Known Issues and Future Features

- [ ] Database query optimization for very large datasets (>1M CVEs)
- [ ] SBOM (Software Bill of Materials) import/export support
- [ ] Integration with CI/CD pipelines for automated security scanning
- [ ] Enhanced wildcard search with fuzzy matching
- [ ] Custom vulnerability scoring based on organizational risk factors
- [ ] Export reports in PDF and CSV formats 