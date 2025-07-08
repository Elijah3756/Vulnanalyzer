#!/bin/bash

# CVE Database Update Script
# This script downloads the latest CVE data from NVD and integrates it with your vulnerability analyzer

set -e  # Exit on any error

# Configuration
DEFAULT_OUTPUT_DIR="./cvelistV5/cves"
DEFAULT_DAYS=30
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Download and update CVE data from the NVD API

OPTIONS:
    -h, --help              Show this help message
    -k, --api-key KEY       NVD API key (recommended for faster downloads)
    -o, --output-dir DIR    Output directory (default: $DEFAULT_OUTPUT_DIR)
    -d, --days DAYS         Download CVEs from last N days (default: $DEFAULT_DAYS)
    -y, --year YEAR         Download CVEs for specific year
    -r, --recent            Download recent CVEs (last 30 days)
    --start-date DATE       Start date for custom range (YYYY-MM-DD)
    --end-date DATE         End date for custom range (YYYY-MM-DD)
    --test                  Test with small sample (last 1 day)

EXAMPLES:
    # Download recent CVEs (last 30 days)
    $0 --recent

    # Download with API key for faster processing
    $0 --api-key YOUR_API_KEY --recent

    # Download specific year
    $0 --year 2024

    # Download date range
    $0 --start-date 2024-01-01 --end-date 2024-03-31

    # Test with small sample
    $0 --test

NOTES:
    - Get a free API key from: https://nvd.nist.gov/developers/request-an-api-key
    - Without API key: 5 requests per 30 seconds
    - With API key: 50 requests per 30 seconds
    - Each year can be 1-2 GB of data
EOF
}

# Check if download script exists
check_dependencies() {
    if [ ! -f "$SCRIPT_DIR/download_cves.py" ]; then
        print_error "download_cves.py not found in $SCRIPT_DIR"
        exit 1
    fi

    if [ ! -f "$SCRIPT_DIR/requirements.txt" ]; then
        print_error "requirements.txt not found in $SCRIPT_DIR"
        exit 1
    fi

    # Check if Python dependencies are installed
    if ! python -c "import requests, tqdm" 2>/dev/null; then
        print_warning "Installing Python dependencies..."
        pip install -r "$SCRIPT_DIR/requirements.txt"
    fi
}

# Test downloaded CVEs with the analyzer
test_integration() {
    local output_dir="$1"
    
    print_info "Testing integration with vulnerability analyzer..."
    
    # Find a sample CVE file
    local sample_cve=$(find "$output_dir" -name "*.json" | head -1)
    
    if [ -z "$sample_cve" ]; then
        print_warning "No CVE files found to test"
        return
    fi
    
    # Extract CVE ID from filename
    local cve_id=$(basename "$sample_cve" .json)
    
    # Test with vulnerability analyzer
    if command -v vuln-analyzer >/dev/null 2>&1; then
        print_info "Testing CVE $cve_id with vulnerability analyzer..."
        if vuln-analyzer "$cve_id" --cve-data-path "$output_dir" >/dev/null 2>&1; then
            print_success "Integration test passed!"
        else
            print_warning "Integration test failed, but CVEs were downloaded successfully"
        fi
    else
        print_warning "vuln-analyzer not found. Install with: uv pip install -e ."
    fi
}

# Main function
main() {
    local api_key=""
    local output_dir="$DEFAULT_OUTPUT_DIR"
    local days=""
    local year=""
    local start_date=""
    local end_date=""
    local test_mode=false
    local recent_mode=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -k|--api-key)
                api_key="$2"
                shift 2
                ;;
            -o|--output-dir)
                output_dir="$2"
                shift 2
                ;;
            -d|--days)
                days="$2"
                shift 2
                ;;
            -y|--year)
                year="$2"
                shift 2
                ;;
            -r|--recent)
                recent_mode=true
                shift
                ;;
            --start-date)
                start_date="$2"
                shift 2
                ;;
            --end-date)
                end_date="$2"
                shift 2
                ;;
            --test)
                test_mode=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done

    print_info "Starting CVE database update..."
    
    # Check dependencies
    check_dependencies

    # Build download command
    local cmd="python $SCRIPT_DIR/download_cves.py --output-dir $output_dir"
    
    if [ -n "$api_key" ]; then
        cmd="$cmd --api-key $api_key"
        print_info "Using API key for faster downloads"
    else
        print_warning "No API key provided. Downloads will be slower (5 req/30s)"
        print_info "Get a free API key: https://nvd.nist.gov/developers/request-an-api-key"
    fi

    # Add specific parameters
    if [ "$test_mode" = true ]; then
        cmd="$cmd --recent-days 1"
        print_info "Test mode: downloading CVEs from last 1 day"
    elif [ -n "$year" ]; then
        cmd="$cmd --year $year"
        print_info "Downloading CVEs for year $year"
    elif [ -n "$start_date" ] && [ -n "$end_date" ]; then
        cmd="$cmd --start-date $start_date --end-date $end_date"
        print_info "Downloading CVEs from $start_date to $end_date"
    elif [ "$recent_mode" = true ] || [ -n "$days" ]; then
        local download_days="${days:-$DEFAULT_DAYS}"
        cmd="$cmd --recent-days $download_days"
        print_info "Downloading CVEs from last $download_days days"
    else
        # Default to recent
        cmd="$cmd --recent-days $DEFAULT_DAYS"
        print_info "Downloading CVEs from last $DEFAULT_DAYS days (default)"
    fi

    # Create output directory
    mkdir -p "$output_dir"
    
    print_info "Output directory: $output_dir"
    print_info "Running: $cmd"
    
    # Execute download
    if eval "$cmd"; then
        print_success "CVE download completed successfully!"
        
        # Show statistics
        local total_files=$(find "$output_dir" -name "*.json" | wc -l)
        local total_years=$(find "$output_dir" -maxdepth 1 -type d | grep -E '/[0-9]{4}$' | wc -l)
        
        print_info "Statistics:"
        print_info "  Total CVE files: $total_files"
        print_info "  Years covered: $total_years"
        print_info "  Storage location: $output_dir"
        
        # Test integration
        test_integration "$output_dir"
        
        print_success "CVE database update completed!"
        print_info "You can now use the vulnerability analyzer with the updated data:"
        print_info "  vuln-analyzer CVE-2024-0001 --cve-data-path $output_dir"
        
    else
        print_error "CVE download failed!"
        exit 1
    fi
}

# Run main function with all arguments
main "$@" 