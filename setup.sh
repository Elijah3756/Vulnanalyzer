#!/bin/bash
set -e

# Vulnerability Analyzer - Containerized Setup Script
# This script sets up the complete containerized environment

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Emoji support
ROCKET=""
CHECK="✅"
WARN="⚠️"
INFO="ℹ️"
GEAR="⚙️"

# Print functions
print_header() {
    echo -e "${PURPLE}================================================${NC}"
    echo -e "${PURPLE}  $1${NC}"
    echo -e "${PURPLE}================================================${NC}"
}

print_info() {
    echo -e "${BLUE}${INFO} $1${NC}"
}

print_success() {
    echo -e "${GREEN}${CHECK} $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}${WARN} $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_step() {
    echo -e "${PURPLE}${GEAR} $1${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
check_requirements() {
    print_step "Checking system requirements..."
    
    local missing_deps=()
    
    if ! command_exists docker; then
        missing_deps+=("docker")
    fi
    
    if ! command_exists docker-compose; then
        missing_deps+=("docker-compose")
    fi
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        print_error "Missing required dependencies: ${missing_deps[*]}"
        echo ""
        echo "Please install the missing dependencies:"
        echo "- Docker: https://docs.docker.com/get-docker/"
        echo "- Docker Compose: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker daemon is not running. Please start Docker and try again."
        exit 1
    fi
    
    print_success "All requirements satisfied!"
}

# Setup environment
setup_environment() {
    print_step "Setting up environment configuration..."
    
    # Environment configuration is handled by the container
    print_info "Environment configuration is handled by container variables"
    
    # Create data directory structure
    mkdir -p data/{cvelistV5/cves,databases,downloads}
    print_success "Created data directory structure"
}

# Build Docker image
build_image() {
    print_step "Building Docker image..."
    
    if docker build -t vuln-analyzer:latest --target production . ; then
        print_success "Docker image built successfully!"
    else
        print_error "Failed to build Docker image"
        exit 1
    fi
}

# Download KEV data
download_kev() {
    print_step "Downloading CISA Known Exploited Vulnerabilities..."
    
    if docker run --rm -v "$(pwd)/data:/app/data" vuln-analyzer:latest download-kev; then
        print_success "KEV data downloaded successfully!"
    else
        print_warning "Failed to download KEV data, continuing anyway..."
    fi
}

# Download recent CVEs
download_recent_cves() {
    print_step "Downloading recent CVE data (last 30 days)..."
    
    # Check if user has API key via environment variable
    if [ ! -z "$NVD_API_KEY" ]; then
        print_info "Using API key for faster downloads"
        if docker-compose --profile download run --rm cve-downloader --recent-days 30; then
            print_success "Recent CVEs downloaded successfully!"
        else
            print_warning "Failed to download recent CVEs"
        fi
    else
        print_warning "No NVD API key found. Downloads will be slower."
        print_info "Get a free API key: https://nvd.nist.gov/developers/request-an-api-key"
        print_info "Set it as environment variable: export NVD_API_KEY=your_key_here"
        
        if docker-compose --profile download run --rm cve-downloader --recent-days 7; then
            print_success "Recent CVEs downloaded successfully (limited to 7 days due to rate limits)!"
        else
            print_warning "Failed to download recent CVEs"
        fi
    fi
}

# Build database
build_database() {
    print_step "Building vulnerability database..."
    
    if docker-compose --profile setup run --rm database-builder; then
        print_success "Database built successfully!"
    else
        print_warning "Failed to build database"
    fi
}

# Run verification tests
run_verification() {
    print_step "Running verification tests..."
    
    # Test container health
    if docker run --rm vuln-analyzer:latest health >/dev/null 2>&1; then
        print_success "Container health check passed"
    else
        print_warning "Container health check failed"
    fi
    
    # Test database
    if [ -f data/databases/cve_database.db ]; then
        print_success "Database file exists"
        
        # Get database stats
        print_info "Database statistics:"
        docker-compose --profile query run --rm query-service stats 2>/dev/null || print_warning "Could not get database stats"
    else
        print_warning "Database file not found"
    fi
}

# Show usage examples
show_examples() {
    print_header "Setup Complete! ${ROCKET}"
    echo ""
    print_success "Vulnerability Analyzer is ready to use!"
    echo ""
    echo -e "${BLUE}Quick Start Examples:${NC}"
    echo ""
    echo "Help and Information:"
    echo "  make help                     # Show all available commands"
    echo "  make docker-run               # Show container help"
    echo ""
    echo "Analysis Examples:"
    echo "  make analyze-cve              # Analyze CVE-2021-44228 (Log4Shell)"
    echo "  make analyze-purl             # Analyze npm lodash package"
    echo "  make analyze-wildcard         # Search Python ecosystem"
    echo "  make analyze-comprehensive    # Comprehensive Apache analysis"
    echo ""
    echo "Database Operations:"
    echo "  make db-stats                 # Show database statistics"
    echo "  make db-query                 # Interactive database queries"
    echo ""
    echo "📥 Data Management:"
    echo "  make download-recent          # Download latest CVEs"
    echo "  make download-year            # Download 2024 CVEs"
    echo ""
    echo "Development:"
    echo "  make dev-up                   # Start development environment"
    echo "  make dev-shell                # Interactive development shell"
    echo ""
    print_info "For more commands, run: make help"
    echo ""
    
    if [ -z "$NVD_API_KEY" ]; then
        print_warning "Recommendation: Get an NVD API key for 50x faster downloads"
        echo "  1. Visit: https://nvd.nist.gov/developers/request-an-api-key"
        echo "  2. Set environment variable: export NVD_API_KEY=your_key_here"
        echo "  3. Run: make download-recent"
        echo ""
    fi
}

# Show setup options
show_options() {
    print_header "Vulnerability Analyzer Setup ${ROCKET}"
    echo ""
    echo "This script will set up the containerized vulnerability analyzer."
    echo ""
    echo "Setup options:"
    echo "  1. Quick setup (recommended) - KEV + recent CVEs + database"
    echo "  2. Minimal setup - KEV only"
    echo "  3. Custom setup - choose components"
    echo "  4. Full setup - download ALL CVEs (takes hours, requires API key)"
    echo ""
    read -p "Choose setup option (1-4) [1]: " setup_choice
    setup_choice=${setup_choice:-1}
}

# Main setup function
main() {
    print_header "Vulnerability Analyzer Setup ${ROCKET}"
    
    # Check if script is run with arguments
    if [ $# -gt 0 ]; then
        case "$1" in
            --quick|quick)
                setup_choice=1
                ;;
            --minimal|minimal)
                setup_choice=2
                ;;
            --full|full)
                setup_choice=4
                ;;
            --help|help|-h)
                echo "Usage: $0 [option]"
                echo ""
                echo "Options:"
                echo "  --quick     Quick setup (default)"
                echo "  --minimal   Minimal setup"
                echo "  --full      Full setup with all CVEs"
                echo "  --help      Show this help"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                echo "Use --help for available options"
                exit 1
                ;;
        esac
    else
        show_options
    fi
    
    echo ""
    print_info "Starting setup process..."
    echo ""
    
    # Core setup steps
    check_requirements
    setup_environment
    build_image
    
    # Setup based on choice
    case "$setup_choice" in
        1) # Quick setup
            print_info "Running quick setup..."
            download_kev
            download_recent_cves
            build_database
            ;;
        2) # Minimal setup
            print_info "Running minimal setup..."
            download_kev
            ;;
        3) # Custom setup
            print_info "Custom setup - choose components:"
            read -p "Download KEV data? (y/n) [y]: " kev_choice
            if [[ ${kev_choice:-y} =~ ^[Yy] ]]; then
                download_kev
            fi
            
            read -p "Download recent CVEs? (y/n) [y]: " cve_choice
            if [[ ${cve_choice:-y} =~ ^[Yy] ]]; then
                download_recent_cves
            fi
            
            read -p "Build database? (y/n) [y]: " db_choice
            if [[ ${db_choice:-y} =~ ^[Yy] ]]; then
                build_database
            fi
            ;;
        4) # Full setup
            print_info "Running full setup (this will take several hours)..."
            download_kev
            print_warning "Full CVE download will take 2-6 hours. Press Ctrl+C to cancel."
            sleep 5
            if docker-compose --profile download run --rm cve-downloader --all --max-retries 10; then
                print_success "All CVEs downloaded!"
            else
                print_warning "Failed to download all CVEs, continuing with recent CVEs..."
                download_recent_cves
            fi
            build_database
            ;;
    esac
    
    # Verification and completion
    run_verification
    show_examples
}

# Handle script interruption
trap 'echo -e "\n${YELLOW}Setup interrupted. You can restart with: ./setup.sh${NC}"; exit 1' INT

# Run main function
main "$@" 