#!/bin/bash
set -e

# Container entrypoint script for vulnerability analyzer
echo "Starting Vulnerability Analyzer Container..."

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Initialize container environment
init_container() {
    log "Initializing container environment..."
    
    # Create required directories if they don't exist
    mkdir -p "${CVE_DATA_PATH}"
    mkdir -p "${DOWNLOAD_DIR}"
    mkdir -p "$(dirname "${DATABASE_PATH}")"
    mkdir -p "$(dirname "${KEV_FILE_PATH}")"
    mkdir -p /app/logs
    
    # Set permissions
    chmod 755 "${CVE_DATA_PATH}" "${DOWNLOAD_DIR}" "$(dirname "${DATABASE_PATH}")"
    
    log "Environment initialized successfully"
    log "CVE Data Path: ${CVE_DATA_PATH}"
    log "Database Path: ${DATABASE_PATH}"
    log "KEV File Path: ${KEV_FILE_PATH}"
    log "Download Directory: ${DOWNLOAD_DIR}"
}

# Download KEV data if not present
download_kev() {
    if [ ! -f "${KEV_FILE_PATH}" ]; then
        log "Downloading CISA Known Exploited Vulnerabilities catalog..."
        curl -s -o "${KEV_FILE_PATH}" \
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" || {
            log "Warning: Failed to download KEV file. Some features may be limited."
        }
    else
        log "KEV file already exists: ${KEV_FILE_PATH}"
    fi
}

# Check if database exists
check_database() {
    if [ -f "${DATABASE_PATH}" ]; then
        log "Database found: ${DATABASE_PATH}"
        # Show database stats
        if command -v sqlite3 >/dev/null 2>&1; then
            CVE_COUNT=$(sqlite3 "${DATABASE_PATH}" "SELECT COUNT(*) FROM cve_records" 2>/dev/null || echo "0")
            KEV_COUNT=$(sqlite3 "${DATABASE_PATH}" "SELECT COUNT(*) FROM known_exploited_vulns" 2>/dev/null || echo "0")
            log "Database contains: ${CVE_COUNT} CVEs, ${KEV_COUNT} KEVs"
        fi
    else
        log "No database found at ${DATABASE_PATH}"
        log "Use 'create-database' command to build database from CVE files"
    fi
}

# Handle different command modes
handle_command() {
    case "$1" in
        "create-database"|"build-database")
            log "Creating vulnerability database..."
            shift
            exec python /app/scripts/create_database.py \
                --cve-dir "${CVE_DATA_PATH}" \
                --kev-file "${KEV_FILE_PATH}" \
                --db-path "${DATABASE_PATH}" \
                --verbose "$@"
            ;;
        "download-cves")
            log "Downloading CVE data..."
            shift
            exec python /app/scripts/download_cves.py \
                --output-dir "${CVE_DATA_PATH}" \
                --verbose "$@"
            ;;
        "download-kev")
            download_kev
            exit 0
            ;;
        "query-database")
            log "Querying database..."
            shift
            exec python /app/scripts/query_database.py \
                --db-path "${DATABASE_PATH}" "$@"
            ;;
        "shell"|"bash")
            log "Starting interactive shell..."
            exec /bin/bash
            ;;
        "init")
            log "Container initialization complete"
            exit 0
            ;;
        "health"|"healthcheck")
            # Health check
            python -c "import vulnanalyzer; print('Container is healthy')"
            exit 0
            ;;
        "--help"|"help")
            show_help
            exit 0
            ;;
        "")
            show_help
            exit 0
            ;;
        *)
            # Pass to vulnerability analyzer
            log "Running vulnerability analysis..."
            exec vulnanalyzer "$@"
            ;;
    esac
}

# Show help information
show_help() {
    cat << EOF
Vulnerability Analyzer Container

USAGE:
    docker run vuln-analyzer [COMMAND] [OPTIONS]

ANALYSIS COMMANDS:
    CVE-2020-0001                 - Analyze specific CVE
    "pkg:npm/lodash@4.17.20"      - Analyze package URL (PURL)  
    "python"                      - Wildcard search for Python vulnerabilities
    --comprehensive "apache *"    - Comprehensive component analysis

CONTAINER COMMANDS:
    create-database              - Build SQLite database from CVE files
    download-cves [OPTIONS]      - Download CVE data from NVD API
    download-kev                 - Download CISA Known Exploited Vulnerabilities
    query-database [QUERY]       - Query the vulnerability database
    shell                        - Start interactive shell
    init                         - Initialize container environment
    health                       - Container health check

EXAMPLES:
    # Analyze CVE with database
    docker run vuln-analyzer cve CVE-2021-44228
    
    # Build database from mounted CVE data
    docker run -v /host/cves:/app/data/cvelistV5/cves vulnanalyzer create-database
    
    # Download recent CVEs
    docker run vulnanalyzer download-cves --recent-days 30
    
    # Comprehensive wildcard analysis
    docker run vulnanalyzer wildcard "python" --comprehensive

ENVIRONMENT VARIABLES:
    CVE_DATA_PATH=/app/data/cvelistV5/cves
    DATABASE_PATH=/app/data/databases/cve_database.db
    KEV_FILE_PATH=/app/data/known_exploited_vulnerabilities.json
    DOWNLOAD_DIR=/app/data/downloads

VOLUME MOUNTS:
    /app/data                    - Persistent data directory
    /app/data/cvelistV5/cves     - CVE data files
    /app/data/databases          - SQLite databases
    /app/config                  - Configuration files

For more information, visit: https://github.com/your-org/vulnanalyzer
EOF
}

# Main execution
main() {
    # Initialize container
    init_container
    
    # Download KEV data if needed
    download_kev
    
    # Check database status
    check_database
    
    # Handle the command
    handle_command "$@"
}

# Run main function with all arguments
main "$@" 