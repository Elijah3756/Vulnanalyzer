# VulnAnalyzer

> Professional vulnerability analysis tool for CVE, PURL, CPE, and wildcard searches

## Overview

VulnAnalyzer is a comprehensive command-line tool for analyzing vulnerability data from multiple sources including the National Vulnerability Database (NVD) and CISA Known Exploited Vulnerabilities (KEV) catalog. It provides detailed risk assessments, vulnerability activity rates, and exploitation risk analysis for software components, platforms, and technologies.

## Features
**Multi-format Support** - Analyze CVE IDs, Package URLs (PURL), Common Platform Enumeration (CPE), and wildcard searches  
**Comprehensive Risk Assessment** - Calculate vulnerability activity rates, exploitation risks, and relative threat levels  
**Professional Output** - Both human-readable text and structured JSON output formats  
**High-Performance Database** - SQLite database for fast queries across large datasets  
**Automatic Updates** - Download and update vulnerability data from official sources  
**Component Analysis** - Detailed breakdown of vulnerability patterns across different components

## Installation

```bash
# Install from PyPI (recommended)
pip install vulnanalyzer

# Or install from source
git clone https://github.com/Elijah3756/vulnerabililizer.git
cd vulnerabililizer
pip install -e .
```

## Quick Start

### Initial Setup
```bash
# Setup database with all CVEs and KEVs
vulnanalyzer setup

# Or with API key for faster downloads
vulnanalyzer setup --api-key YOUR_NVD_API_KEY
```

### Basic Usage
```bash
# Analyze a specific CVE
vulnanalyzer cve CVE-2021-44228

# Analyze a package URL
vulnanalyzer purl "pkg:npm/lodash@4.17.20"

# Perform wildcard search
vulnanalyzer wildcard "python"

# Comprehensive analysis
vulnanalyzer purl "pkg:npm/express@4.17.1" --comprehensive
```

## Commands

| Command | Description | Example |
|---------|-------------|---------|
| `setup` | Initialize database with CVE/KEV data | `vulnanalyzer setup` |
| `update` | Update with recent vulnerability data | `vulnanalyzer update --days 7` |
| `cve` | Analyze a CVE identifier | `vulnanalyzer cve CVE-2021-44228` |
| `purl` | Analyze a Package URL | `vulnanalyzer purl "pkg:npm/lodash@4.17.20"` |
| `cpe` | Analyze a CPE identifier | `vulnanalyzer cpe "cpe:2.3:a:apache:http_server:2.4.41"` |
| `wildcard` | Perform wildcard search | `vulnanalyzer wildcard "python"` |

## Examples

### CVE Analysis
```bash
vulnanalyzer cve CVE-2021-44228 --output-format json
```

### Package Security Assessment
```bash
vulnanalyzer purl "pkg:npm/express@4.17.1" --comprehensive
```

### Technology Ecosystem Analysis
```bash
vulnanalyzer wildcard "nodejs" --output-format both
```

### Platform Vulnerability Assessment
```bash
vulnanalyzer cpe "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
```

## Output Formats

**Text Output** - Human-readable analysis with risk metrics, interpretations, and recommendations

**JSON Output** - Structured data for programmatic processing:
```json
{
  "identifier": "CVE-2021-44228",
  "input_type": "cve",
  "matched_cves": ["CVE-2021-44228", "CVE-2021-45046"],
  "vulnerability_activity_rate": 2.5,
  "exploitation_risk": 0.12,
  "relative_threat_level": 0.003,
  "metadata": {...}
}
```

## Configuration

### API Key Setup
Get a free API key from NVD for faster downloads:
1. Visit: https://nvd.nist.gov/developers/request-an-api-key
2. Use with: `vulnanalyzer setup --api-key YOUR_KEY`

### Data Directory
```
~/.vulnanalyzer/
├── cvelistV5/cves/           # CVE JSON files
├── databases/                # SQLite databases
├── downloads/                # Downloaded data
└── known_exploited_vulnerabilities.json
```

## Development

### Prerequisites
- Python 3.9+
- pip or uv package manager

### Setup
```bash
git clone https://github.com/Elijah3756/vulnerabililizer.git
cd vulnerabililizer
pip install -e ".[dev]"
```

## Data Sources

- **NVD API v2.0** - Primary source for CVE data
- **CISA KEV Catalog** - Known exploited vulnerabilities
- **CVE Record Format 5.x** - Standardized vulnerability data

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/Elijah3756/vulnerabililizer/issues)
- **Documentation**: [README](https://github.com/Elijah3756/vulnerabililizer#readme)
- **Repository**: [GitHub](https://github.com/Elijah3756/vulnerabililizer)

---

**Acknowledgments**: NVD for vulnerability data, CISA for KEV catalog, and the security research community. 