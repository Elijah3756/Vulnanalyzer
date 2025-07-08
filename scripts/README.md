# CVE Download Script

This script downloads CVE data from the [NVD (National Vulnerability Database) API](https://nvd.nist.gov/developers) and saves it in a format compatible with the vulnerability analyzer.

## Features

- ✅ Uses official NVD API (not web scraping)
- ✅ Respects rate limits (5 requests/30s without API key, 50 requests/30s with API key)
- ✅ Downloads by year, date range, or recent days
- ✅ Saves in CVE Record Format 5.x compatible structure
- ✅ Organizes files by year and CVE number ranges
- ✅ Progress tracking and robust error handling

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or install with uv
uv pip install -r requirements.txt
```

## API Key (Recommended)

To avoid rate limits, request a free API key from the NVD:

1. Go to: https://nvd.nist.gov/developers/request-an-api-key
2. Fill out the form and submit
3. You'll receive an API key via email
4. Use the key with the `--api-key` parameter

## Usage

### Basic Usage

```bash
# Download CVEs from the last 30 days
python download_cves.py

# Download CVEs from the last 7 days
python download_cves.py --recent-days 7

# Download CVEs for a specific year
python download_cves.py --year 2024

# Download CVEs for a date range
python download_cves.py --start-date 2024-01-01 --end-date 2024-12-31

# Download ALL CVEs from the NVD database (comprehensive)
python download_cves.py --all
```

### With API Key

```bash
# Using API key for higher rate limits
python download_cves.py --api-key YOUR_API_KEY --year 2024

# Download all CVEs with API key (recommended for large downloads)
python download_cves.py --api-key YOUR_API_KEY --all

# Set as environment variable
export NVD_API_KEY=your_api_key_here
python download_cves.py --api-key $NVD_API_KEY --all
```

### Custom Output Directory

```bash
# Specify custom output directory
python download_cves.py --output-dir ./my_cves --year 2024

# Download to match your existing structure
python download_cves.py --output-dir ./cvelistV5/cves --year 2024
```

## Rate Limits

The NVD API has rate limits to prevent abuse:

- **Without API key**: 5 requests per 30 seconds
- **With API key**: 50 requests per 30 seconds

The script automatically handles rate limiting and will pause when necessary.

## Output Format

The script saves CVEs in the following directory structure:

```
downloaded_cves/
├── 2024/
│   ├── 0xxx/
│   │   ├── CVE-2024-0001.json
│   │   └── CVE-2024-0999.json
│   ├── 1xxx/
│   │   ├── CVE-2024-1000.json
│   │   └── CVE-2024-1999.json
│   └── ...
├── 2023/
│   └── ...
└── 2022/
    └── ...
```

Each CVE file contains data in CVE Record Format 5.x, compatible with your vulnerability analyzer.

## Examples

### Download Recent CVEs

```bash
# Last 30 days (default)
python download_cves.py

# Last 7 days
python download_cves.py --recent-days 7
```

### Download by Year

```bash
# Download 2024 CVEs
python download_cves.py --year 2024

# Download 2023 CVEs with API key
python download_cves.py --api-key YOUR_KEY --year 2023
```

### Download by Date Range

```bash
# Download Q1 2024
python download_cves.py --start-date 2024-01-01 --end-date 2024-03-31

# Download January 2024
python download_cves.py --start-date 2024-01-01 --end-date 2024-01-31
```

### Batch Download Multiple Years

```bash
# Download last 5 years
for year in {2020..2024}; do
  python download_cves.py --year $year --output-dir ./cvelistV5/cves
  sleep 60  # Wait between years to be respectful
done
```

### Comprehensive Download (All CVEs)

The `--all` option downloads the complete CVE database from NVD. This is useful for:

- **Complete vulnerability analysis**: Access to all historical and current vulnerabilities
- **Offline analysis**: Work with the full dataset without internet dependency
- **Research and development**: Comprehensive testing and validation

**Important considerations:**

- **Time**: Downloading all CVEs can take 2-6 hours depending on your connection and API key
- **Storage**: Requires 2-4 GB of disk space for the complete dataset
- **Rate limits**: Without an API key, this will take much longer due to rate limiting
- **API key recommended**: Get a free API key for 10x faster downloads

```bash
# Download all CVEs (with API key recommended)
python download_cves.py --api-key YOUR_API_KEY --all --output-dir ./cvelistV5/cves

# Monitor progress - the script shows download progress
# Example output:
# 2024-01-01 10:00:00 - INFO - Downloading ALL CVEs from NVD database...
# 2024-01-01 10:00:01 - INFO - Fetching results 0 to 2000
# 2024-01-01 10:00:05 - INFO - Progress: 2000 / 285000 CVEs downloaded
# 2024-01-01 10:00:10 - INFO - Fetching results 2000 to 4000
# ...
```

## Integration with Vulnerability Analyzer

After downloading CVEs, you can use them with your vulnerability analyzer:

```bash
# Download CVEs to match your existing structure
python download_cves.py --output-dir ./cvelistV5/cves --year 2024

# Test with your analyzer
vuln-analyzer CVE-2024-0001 --cve-data-path ./cvelistV5/cves
```

## Error Handling

The script includes robust error handling:

- **Network errors**: Automatically retries failed requests
- **Rate limiting**: Respects API rate limits with automatic pausing
- **Invalid data**: Skips malformed CVE records with logging
- **File errors**: Continues processing even if individual files fail

### Error Handling and Retry Logic

The download script includes robust error handling for common API issues:

#### 429 Too Many Requests
- **Automatic Detection**: Detects 429 errors and waits before retrying
- **Exponential Backoff**: Increases wait time with each retry (60s → 120s → 240s → 480s)
- **Rate Limit Reset**: Resets internal rate limiting after 429 errors
- **Configurable Delays**: Customize base delay and maximum delay

#### Other Error Types
- **500 Server Errors**: Retries with exponential backoff
- **Connection Errors**: Handles network timeouts and connection issues
- **Timeout Errors**: Retries requests that exceed 30-second timeout
- **Consecutive Failures**: Stops after 5 consecutive failures to prevent infinite loops

#### Retry Configuration
```bash
# Custom retry settings
python download_cves.py --all \
  --max-retries 10 \
  --retry-delay 180 \
  --max-retry-delay 1200 \
  --verbose

# Conservative settings for unstable connections
python download_cves.py --all \
  --max-retries 15 \
  --retry-delay 300 \
  --max-retry-delay 1800
```

#### Download Statistics
The script tracks and reports:
- Total requests made
- Successful vs failed requests
- Rate limit hits
- Retry attempts
- Success rate percentage

Example output:
```
Download completed!
Statistics:
  Total Requests: 150
  Successful: 145
  Failed: 5
  Rate Limit Hits: 3
  Retries: 8
  Success Rate: 96.7%
```

## Logging

The script provides detailed logging:

```
2024-01-01 10:00:00 - INFO - Downloading CVEs for year 2024
2024-01-01 10:00:01 - INFO - Fetching results 0 to 2000
2024-01-01 10:00:05 - INFO - Fetching results 2000 to 4000
2024-01-01 10:00:10 - WARNING - Rate limit exceeded (429). Retrying in 120 seconds... (attempt 1/4)
2024-01-01 10:02:30 - INFO - Downloaded 15420 CVEs
2024-01-01 10:02:31 - INFO - Saving 15420 CVEs to files...
2024-01-01 10:04:15 - INFO - CVE data saved successfully!
```

## Performance Tips

1. **Use an API key** for 10x faster downloads
2. **Download by year** for large datasets
3. **Use appropriate date ranges** to avoid unnecessary data
4. **Monitor rate limits** - the script handles this automatically
5. **Use SSD storage** for better file I/O performance
6. **Use robust retry settings** for large downloads: `--max-retries 10 --retry-delay 180`

## Troubleshooting

### Common Issues

1. **Rate limit errors (429)**: The script now handles these automatically with exponential backoff
2. **Network timeouts**: Check your internet connection and use `--max-retries` to increase retry attempts
3. **Disk space**: Ensure sufficient space (each year can be 1-2 GB)
4. **Permission errors**: Check write permissions for output directory
5. **API key issues**: Verify your API key is valid and not expired

### Getting Help

- Check the NVD API documentation: https://nvd.nist.gov/developers
- Review the script logs for detailed error messages
- Use `--verbose` flag for more detailed logging
- Check download statistics for success rates and error patterns

## Data Quality

The NVD API provides high-quality, authoritative vulnerability data:

- **Official source**: Maintained by NIST
- **Comprehensive**: 285,000+ CVEs as of 2024
- **Up-to-date**: New vulnerabilities added daily
- **Standardized**: Consistent format and structure
- **Enriched**: Includes CVSS scores, CWE mappings, and CPE data

This data is much more reliable than web scraping and is the recommended approach for vulnerability research and analysis.
