# Vulnerability Analyzer

A containerized CLI tool for analyzing vulnerability data using CVE, PURL, or CPE identifiers. This tool provides vulnerability introduction rates and historical usage rates by analyzing the extensive CVE database.

## Features

- **Multi-format Support**: Analyze CVE IDs, Package URLs (PURL), or Common Platform Enumeration (CPE)
- **Comprehensive Analysis**: Calculate vulnerability introduction rates and historical usage rates
- **Database System**: SQLite database for lightning-fast queries (200-500x faster than file-based)
- **Containerized**: Ready-to-use Docker container with all dependencies
- **Fast Performance**: Intelligent caching and optimized data processing
- **Flexible Output**: JSON or human-readable output formats

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

### Docker Examples

```bash
# Basic CVE analysis
docker run --rm vuln-analyzer CVE-2020-0001

# Package analysis with verbose output
docker run --rm vuln-analyzer -v "pkg:npm/express@4.17.1"

# CPE analysis with pretty output
docker run --rm vuln-analyzer --output-format pretty "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

# Mount custom CVE data directory
docker run --rm -v /path/to/cvelistV5:/app/cvelistV5 vuln-analyzer CVE-2020-0001
```

## Output Format

### JSON Output (Default)

```json
{
  "identifier": "CVE-2020-0001",
  "input_type": "cve",
  "matched_cves": ["CVE-2020-0001", "CVE-2020-0002", "..."],
  "introduction_rate": 0.0234,
  "history_usage_rate": 0.0156,
  "analysis_period": "Year 2020",
  "total_cves_analyzed": 15420,
  "error_message": null,
  "metadata": {
    "vendor": "google_android",
    "product": "Android",
    "published_date": "2020-01-08T18:25:12+00:00",
    "problem_types": ["Elevation of privilege"]
  }
}
```

### Pretty Output

```
Analysis Results for CVE-2020-0001
==================================================
Input Type: CVE
Matched CVEs: 15
Vulnerability Introduction Rate: 2.34%
History Usage Rate: 1.56%
Analysis Period: Year 2020

Matched CVEs:
  - CVE-2020-0001
  - CVE-2020-0002
  - CVE-2020-0003
  ... and 12 more
```

## Supported Input Types

### CVE IDs
- Format: `CVE-YYYY-NNNN` (e.g., `CVE-2020-0001`)
- Analysis: Finds related vulnerabilities in the same vendor/product

### Package URLs (PURL)
- Format: `pkg:type/namespace/name@version` (e.g., `pkg:npm/lodash@4.17.20`)
- Analysis: Searches for vulnerabilities affecting the specific package

### Common Platform Enumeration (CPE)
- Format: `cpe:version:part:vendor:product:version:update:edition:language`
- Example: `cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*`
- Analysis: Finds vulnerabilities for the specified platform/software

## Configuration

### Environment Variables

- `CVE_DATA_PATH`: Path to CVE data directory (default: `./cvelistV5/cves`)
- `PYTHONPATH`: Python path for module imports

### Command Line Options

- `--input-type`: Specify input type (cve, purl, cpe)
- `--cve-data-path`: Path to CVE data directory
- `--use-database`: Use SQLite database for faster queries
- `--output-format`: Output format (json, pretty)
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