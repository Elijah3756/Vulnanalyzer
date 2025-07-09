# VulnAnalyzer

Professional vulnerability analysis tool for CVE, PURL, CPE, and wildcard searches.

## Overview

VulnAnalyzer is a comprehensive command-line tool for analyzing vulnerability data from multiple sources including the National Vulnerability Database (NVD) and CISA Known Exploited Vulnerabilities (KEV) catalog. It provides detailed risk assessments, vulnerability activity rates, and exploitation risk analysis for software components, platforms, and technologies.

## Features

- **Multi-format Support**: Analyze CVE IDs, Package URLs (PURL), Common Platform Enumeration (CPE), and wildcard searches
- **Comprehensive Risk Assessment**: Calculate vulnerability activity rates, exploitation risks, and relative threat levels
- **Professional Output**: Both human-readable text and structured JSON output formats
- **Database Integration**: High-performance SQLite database for fast queries across large datasets
- **Automatic Updates**: Download and update vulnerability data from official sources
- **Component Analysis**: Detailed breakdown of vulnerability patterns across different components

## Installation

### From PyPI (Recommended)

```bash
pip install vulnanalyzer
```

### From Source

```bash
git clone https://github.com/your-org/vulnanalyzer.git
cd vulnanalyzer
pip install -e .
```

## Quick Start

### Initial Setup

```bash
# Setup database with all CVEs and KEVs (recommended for first use)
vulnanalyzer setup

# Or setup with API key for faster downloads
vulnanalyzer setup --api-key YOUR_NVD_API_KEY
```

### Basic Usage

```bash
# Analyze a specific CVE
vulnanalyzer cve CVE-2021-44228

# Analyze a package URL
vulnanalyzer purl "pkg:npm/lodash@4.17.20"

# Analyze a CPE identifier
vulnanalyzer cpe "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"

# Perform wildcard search
vulnanalyzer wildcard "python"

# Comprehensive component analysis
vulnanalyzer purl "pkg:npm/express@4.17.1" --comprehensive
```

### Updating Data

```bash
# Update with recent vulnerability data (last 30 days)
vulnanalyzer update

# Update with custom time range
vulnanalyzer update --days 7
```

## Command Reference

### Analysis Commands

#### CVE Analysis
```bash
vulnanalyzer cve CVE-2021-44228 [--output-format {text,json,both}]
```

#### PURL Analysis
```bash
vulnanalyzer purl "pkg:npm/lodash@4.17.20" [--comprehensive] [--output-format {text,json,both}]
```

#### CPE Analysis
```bash
vulnanalyzer cpe "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*" [--comprehensive] [--output-format {text,json,both}]
```

#### Wildcard Search
```bash
vulnanalyzer wildcard "python" [--output-format {text,json,both}]
```

### Database Management

#### Setup Database
```bash
vulnanalyzer setup [--api-key KEY] [--verbose]
```

#### Update Data
```bash
vulnanalyzer update [--days DAYS] [--api-key KEY] [--verbose]
```

### Global Options

- `--verbose, -v`: Enable verbose output
- `--api-key`: NVD API key for faster downloads
- `--output-format`: Output format (text, json, or both)

## Output Formats

### Text Output

The text output provides human-readable analysis results including:

- Risk metrics and interpretations
- Vulnerability activity rates
- Exploitation risk assessments
- Detailed component information
- Sample matched CVEs
- Security recommendations

### JSON Output

The JSON output provides structured data suitable for programmatic processing:

```json
{
  "identifier": "CVE-2021-44228",
  "input_type": "cve",
  "matched_cves": ["CVE-2021-44228", "CVE-2021-45046"],
  "introduction_rate": 0.15,
  "history_usage_rate": 0.08,
  "vulnerability_activity_rate": 2.5,
  "exploitation_risk": 0.12,
  "relative_threat_level": 0.003,
  "metadata": {
    "vendor": "apache",
    "product": "log4j",
    "risk_summary": {...}
  }
}
```

## API Key Configuration

For faster downloads and higher rate limits, obtain a free API key from the NVD:

1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the form and submit
3. Use the key with the `--api-key` parameter

Without an API key, downloads are limited to 5 requests per 30 seconds. With an API key, this increases to 50 requests per 30 seconds.

## Data Sources

- **NVD API v2.0**: Primary source for CVE data
- **CISA KEV Catalog**: Known exploited vulnerabilities
- **CVE Record Format 5.x**: Standardized vulnerability data format

## Database Schema

The tool creates a SQLite database with the following structure:

- `cve_records`: Primary CVE metadata
- `cve_descriptions`: Multi-language descriptions
- `cve_affected`: Vendor/product mappings
- `cve_references`: External links and tags
- `cve_problem_types`: CWE classifications
- `known_exploited_vulns`: CISA catalog integration
- `cve_search`: Full-text search index

## Risk Metrics

### Vulnerability Activity Rate
Measures how active a component is in terms of recent vulnerabilities compared to historical patterns.

### Exploitation Risk
Percentage of vulnerabilities for a component that have been exploited in the wild.

### Relative Threat Level
How a component compares to the overall threat landscape in terms of known exploited vulnerabilities.

## Examples

### Analyzing Log4Shell
```bash
vulnanalyzer cve CVE-2021-44228
```

### Package Security Assessment
```bash
vulnanalyzer purl "pkg:npm/express@4.17.1" --comprehensive
```

### Technology Ecosystem Analysis
```bash
vulnanalyzer wildcard "nodejs"
```

### Platform Vulnerability Assessment
```bash
vulnanalyzer cpe "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*" --comprehensive
```

## Configuration

### Environment Variables

- `VULNANALYZER_DATA`: Custom data directory path (default: `~/.vulnanalyzer`)

### Data Directory Structure

```
~/.vulnanalyzer/
├── cvelistV5/cves/           # CVE JSON files
├── databases/                # SQLite databases
├── downloads/                # Downloaded data
└── known_exploited_vulnerabilities.json
```

## Performance

- **Database Queries**: 200-500x faster than file-based analysis
- **Storage Efficiency**: 60% smaller than raw JSON files
- **Memory Usage**: Optimized for large datasets
- **Concurrent Operations**: Thread-safe database operations

## Development

### Prerequisites

- Python 3.9+
- pip or uv package manager

### Development Setup

```bash
git clone https://github.com/your-org/vulnanalyzer.git
cd vulnanalyzer
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Code Quality

```bash
black src/vulnanalyzer/
flake8 src/vulnanalyzer/
mypy src/vulnanalyzer/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Support

- **Documentation**: https://github.com/your-org/vulnanalyzer#readme
- **Issues**: https://github.com/your-org/vulnanalyzer/issues
- **Discussions**: https://github.com/your-org/vulnanalyzer/discussions

## Acknowledgments

- NVD for providing comprehensive vulnerability data
- CISA for maintaining the Known Exploited Vulnerabilities catalog
- The security research community for continuous vulnerability analysis 