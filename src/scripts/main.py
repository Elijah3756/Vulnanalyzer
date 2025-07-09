#!/usr/bin/env python3
"""
Main entry point for the vulnerability analyzer container and CLI.
Handles container initialization, data management, and all command routing.
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from vulnanalyzer.cli import main as vulnanalyzer_main


class ContainerManager:
    """Manages container operations and command routing."""
    
    def __init__(self):
        """Initialize the container manager."""
        self.logger = self._setup_logger()
        
        # Environment variables
        self.cve_data_path = Path(os.getenv('CVE_DATA_PATH', '/app/data/cvelistV5/cves'))
        self.database_path = Path(os.getenv('DATABASE_PATH', '/app/data/databases/cve_database.db'))
        self.kev_file_path = Path(os.getenv('KEV_FILE_PATH', '/app/data/known_exploited_vulnerabilities_catalog.json'))
        self.download_dir = Path(os.getenv('DOWNLOAD_DIR', '/app/data/downloads'))
        
        self.log(f"Container environment initialized")
        self.log(f"CVE Data Path: {self.cve_data_path}")
        self.log(f"Database Path: {self.database_path}")
        self.log(f"KEV File Path: {self.kev_file_path}")
        self.log(f"Download Directory: {self.download_dir}")
    
    def _setup_logger(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def log(self, message: str) -> None:
        """Log a message with timestamp."""
        self.logger.info(message)
    
    def init_container(self) -> None:
        """Initialize container environment."""
        self.log("Initializing container environment...")
        
        # Create required directories
        directories = [
            self.cve_data_path,
            self.download_dir,
            self.database_path.parent,
            self.kev_file_path.parent,
            Path('/app/logs')
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            # Set permissions
            try:
                os.chmod(directory, 0o755)
            except Exception:
                pass  # Ignore permission errors in containers
        
        self.log("Environment initialized successfully")
    
    def download_kev(self) -> bool:
        """Download KEV data if not present."""
        if self.kev_file_path.exists():
            self.log(f"KEV file already exists: {self.kev_file_path}")
            return True
        
        self.log("Downloading CISA Known Exploited Vulnerabilities catalog...")
        try:
            import requests
            response = requests.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                timeout=30
            )
            response.raise_for_status()
            
            with open(self.kev_file_path, 'w', encoding='utf-8') as f:
                json.dump(response.json(), f, indent=2)
            
            self.log(f"KEV file downloaded successfully: {self.kev_file_path}")
            return True
            
        except Exception as e:
            self.log(f"Warning: Failed to download KEV file: {e}")
            self.log("Some features may be limited.")
            return False
    
    def check_database(self) -> None:
        """Check if database exists and show stats."""
        if self.database_path.exists():
            self.log(f"Database found: {self.database_path}")
            
            # Try to show database stats
            try:
                import sqlite3
                conn = sqlite3.connect(self.database_path)
                
                # Get CVE count
                cursor = conn.execute("SELECT COUNT(*) FROM cve_records")
                cve_count = cursor.fetchone()[0]
                
                # Get KEV count
                cursor = conn.execute("SELECT COUNT(*) FROM known_exploited_vulns")
                kev_count = cursor.fetchone()[0]
                
                self.log(f"Database contains: {cve_count:,} CVEs, {kev_count:,} KEVs")
                conn.close()
                
            except Exception as e:
                self.log(f"Could not read database stats: {e}")
        else:
            self.log(f"No database found at {self.database_path}")
            self.log("Use 'create-database' command to build database from CVE files")
    
    def run_script(self, script_name: str, args: List[str]) -> int:
        """Run a script from the scripts directory."""
        script_path = Path(__file__).parent / f"{script_name}.py"
        
        if not script_path.exists():
            self.log(f"Error: Script not found: {script_path}")
            return 1
        
        try:
            cmd = [sys.executable, str(script_path)] + args
            result = subprocess.run(cmd, check=False)
            return result.returncode
        except Exception as e:
            self.log(f"Error running script {script_name}: {e}")
            return 1
    
    def health_check(self) -> int:
        """Container health check."""
        try:
            # Test import
            import vulnanalyzer
            
            # Check if essential directories exist
            essential_dirs = [self.cve_data_path.parent, self.database_path.parent]
            for directory in essential_dirs:
                if not directory.exists():
                    self.log(f"Health check failed: Missing directory {directory}")
                    return 1
            
            print("Container is healthy")
            return 0
            
        except Exception as e:
            self.log(f"Health check failed: {e}")
            return 1
    
    def show_help(self) -> None:
        """Show help information."""
        help_text = """
Vulnerability Analyzer Container

USAGE:
    docker run vuln-analyzer [COMMAND] [OPTIONS]

ANALYSIS COMMANDS:
    cve CVE-2020-0001                     - Analyze specific CVE
    purl "pkg:npm/lodash@4.17.20"         - Analyze package URL (PURL)  
    cpe "cpe:2.3:a:apache:http_server:*"  - Analyze CPE
    wildcard "python"                     - Wildcard search for Python vulnerabilities
    --comprehensive "apache *"            - Comprehensive component analysis

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
    KEV_FILE_PATH=/app/data/known_exploited_vulnerabilities_catalog.json
    DOWNLOAD_DIR=/app/data/downloads

VOLUME MOUNTS:
    /app/data                    - Persistent data directory
    /app/data/cvelistV5/cves     - CVE data files
    /app/data/databases          - SQLite databases
    /app/config                  - Configuration files

For more information, visit: https://github.com/Elijah3756/vulnerabililizer
"""
        print(help_text)


def create_parser() -> argparse.ArgumentParser:
    """Create the main argument parser with all subcommands."""
    parser = argparse.ArgumentParser(
        prog="vulnanalyzer",
        description="Professional vulnerability analysis tool for CVE, PURL, CPE, and wildcard searches",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  vulnanalyzer cve CVE-2021-44228
  vulnanalyzer purl "pkg:npm/lodash@4.17.20" --comprehensive
  vulnanalyzer cpe "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
  vulnanalyzer wildcard "python"
  vulnanalyzer setup
  vulnanalyzer update --days 7
  vulnanalyzer create-database --verbose
  vulnanalyzer download-cves --year 2024 --api-key YOUR_KEY
  vulnanalyzer query-database stats
        """
    )
    
    # Global options
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--api-key",
        help="NVD API key for faster downloads (get from https://nvd.nist.gov/developers/request-an-api-key)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # ========== ANALYSIS COMMANDS ==========
    
    # CVE Analysis
    cve_parser = subparsers.add_parser("cve", help="Analyze a CVE identifier")
    cve_parser.add_argument("identifier", help="CVE identifier (e.g., CVE-2021-44228)")
    cve_parser.add_argument("--comprehensive", action="store_true", help="Perform comprehensive analysis")
    cve_parser.add_argument("--output-format", choices=["text", "json", "both"], default="both", help="Output format")
    
    # PURL Analysis
    purl_parser = subparsers.add_parser("purl", help="Analyze a Package URL (PURL)")
    purl_parser.add_argument("identifier", help="Package URL (e.g., pkg:npm/lodash@4.17.20)")
    purl_parser.add_argument("--comprehensive", action="store_true", help="Perform comprehensive component analysis")
    purl_parser.add_argument("--output-format", choices=["text", "json", "both"], default="both", help="Output format")
    
    # CPE Analysis
    cpe_parser = subparsers.add_parser("cpe", help="Analyze a Common Platform Enumeration (CPE)")
    cpe_parser.add_argument("identifier", help="CPE identifier (e.g., cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*)")
    cpe_parser.add_argument("--comprehensive", action="store_true", help="Perform comprehensive component analysis")
    cpe_parser.add_argument("--output-format", choices=["text", "json", "both"], default="both", help="Output format")
    
    # Wildcard Analysis
    wildcard_parser = subparsers.add_parser("wildcard", help="Perform wildcard vulnerability search")
    wildcard_parser.add_argument("identifier", help="Search term (e.g., python, apache, nodejs)")
    wildcard_parser.add_argument("--comprehensive", action="store_true", help="Perform comprehensive analysis")
    wildcard_parser.add_argument("--output-format", choices=["text", "json", "both"], default="both", help="Output format")
    
    # ========== SETUP AND UPDATE COMMANDS ==========
    
    # Setup Command
    setup_parser = subparsers.add_parser("setup", help="Setup database with all CVEs and KEVs")
    
    # Update Command
    update_parser = subparsers.add_parser("update", help="Update with recent vulnerability data")
    update_parser.add_argument("--days", type=int, default=30, help="Number of days to look back for recent CVEs")
    
    # ========== DATABASE COMMANDS ==========
    
    # Create Database
    create_db_parser = subparsers.add_parser("create-database", help="Build SQLite database from CVE files")
    create_db_parser.add_argument(
        "--cve-dir", type=Path,
        default=os.path.expanduser('~/.vulnanalyzer/cvelistV5/cves'),
        help="CVE data directory"
    )
    create_db_parser.add_argument(
        "--kev-file", type=Path,
        default=os.path.expanduser('~/.vulnanalyzer/known_exploited_vulnerabilities_catalog.json'),
        help="Known exploited vulnerabilities JSON file"
    )
    create_db_parser.add_argument(
        "--db-path",
        default=os.path.expanduser('~/.vulnanalyzer/databases/cve_database.db'),
        help="Output database path"
    )
    create_db_parser.add_argument("--clear", action="store_true", help="Clear existing database")
    create_db_parser.add_argument("--stats-only", action="store_true", help="Show database statistics only")
    
    # Download CVEs
    download_parser = subparsers.add_parser("download-cves", help="Download CVE data from NVD API")
    download_parser.add_argument(
        "--output-dir",
        default=os.path.expanduser('~/.vulnanalyzer/cvelistV5/cves'),
        help="Output directory for CVE data"
    )
    download_parser.add_argument("--year", type=int, help="Download CVEs for a specific year")
    download_parser.add_argument("--recent-days", type=int, default=30, help="Download CVEs from the last N days")
    download_parser.add_argument("--start-date", help="Start date (YYYY-MM-DD) for custom date range")
    download_parser.add_argument("--end-date", help="End date (YYYY-MM-DD) for custom date range")
    download_parser.add_argument("--all", action="store_true", help="Download ALL CVEs from the NVD database")
    download_parser.add_argument("--max-retries", type=int, default=3, help="Maximum number of retries for failed requests")
    download_parser.add_argument("--retry-delay", type=int, default=60, help="Base delay in seconds for retries")
    download_parser.add_argument("--max-retry-delay", type=int, default=600, help="Maximum delay in seconds for retries")
    
    # Query Database
    query_parser = subparsers.add_parser("query-database", help="Query the vulnerability database")
    query_parser.add_argument(
        "--db-path",
        default=os.path.expanduser('~/.vulnanalyzer/databases/cve_database.db'),
        help="Path to CVE database"
    )
    
    query_subparsers = query_parser.add_subparsers(dest='query_command', help='Query commands')
    
    # Query: Stats
    query_subparsers.add_parser('stats', help='Show database statistics')
    
    # Query: CVE
    query_cve_parser = query_subparsers.add_parser('cve', help='Search for specific CVE')
    query_cve_parser.add_argument('cve_id', help='CVE ID to search for')
    
    # Query: Vendor
    query_vendor_parser = query_subparsers.add_parser('vendor', help='Search CVEs by vendor')
    query_vendor_parser.add_argument('vendor_name', help='Vendor name to search for')
    query_vendor_parser.add_argument('--limit', type=int, default=20, help='Limit results')
    
    # Query: Product
    query_product_parser = query_subparsers.add_parser('product', help='Search CVEs by product')
    query_product_parser.add_argument('product_name', help='Product name to search for')
    query_product_parser.add_argument('--limit', type=int, default=20, help='Limit results')
    
    # Query: KEV
    query_kev_parser = query_subparsers.add_parser('kev', help='Show known exploited vulnerabilities')
    query_kev_parser.add_argument('--limit', type=int, default=20, help='Limit results')
    
    # Query: Years
    query_years_parser = query_subparsers.add_parser('years', help='Show statistics by year')
    query_years_parser.add_argument('--years', type=int, default=10, help='Number of years to show')
    
    # Query: Top Vendors
    query_top_parser = query_subparsers.add_parser('top-vendors', help='Show top vendors by CVE count')
    query_top_parser.add_argument('--limit', type=int, default=10, help='Limit results')
    
    # Query: Search
    query_search_parser = query_subparsers.add_parser('search', help='Full-text search')
    query_search_parser.add_argument('query', help='Search query')
    query_search_parser.add_argument('--limit', type=int, default=20, help='Limit results')
    
    # ========== CONTAINER COMMANDS ==========
    
    # Download KEV
    subparsers.add_parser("download-kev", help="Download CISA Known Exploited Vulnerabilities")
    
    # Shell
    subparsers.add_parser("shell", help="Start interactive shell")
    subparsers.add_parser("bash", help="Start interactive shell (alias)")
    
    # Container Management
    subparsers.add_parser("init", help="Initialize container environment")
    subparsers.add_parser("health", help="Container health check")
    subparsers.add_parser("healthcheck", help="Container health check (alias)")
    
    return parser


def main() -> int:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Check if we're in container mode (if we detect container paths)
    is_container = Path('/app/data').exists()
    
    if is_container:
        # Container mode - use ContainerManager
        manager = ContainerManager()
        
        try:
            # Initialize container
            manager.init_container()
            
            # Download KEV data if needed
            manager.download_kev()
            
            # Check database status
            manager.check_database()
            
            # Handle container-specific commands
            if not args.command:
                manager.show_help()
                return 0
            
            # Route container commands
            if args.command in ["create-database", "build-database"]:
                manager.log("Creating vulnerability database...")
                cmd_args = [
                    "--cve-dir", str(manager.cve_data_path),
                    "--kev-file", str(manager.kev_file_path),
                    "--db-path", str(manager.database_path)
                ]
                if args.verbose:
                    cmd_args.append("--verbose")
                if hasattr(args, 'clear') and args.clear:
                    cmd_args.append("--clear")
                if hasattr(args, 'stats_only') and args.stats_only:
                    cmd_args.append("--stats-only")
                return manager.run_script("create_database", cmd_args)
            
            elif args.command == "download-cves":
                manager.log("Downloading CVE data...")
                cmd_args = ["--output-dir", str(manager.cve_data_path)]
                if args.verbose:
                    cmd_args.append("--verbose")
                if hasattr(args, 'api_key') and args.api_key:
                    cmd_args.extend(["--api-key", args.api_key])
                if hasattr(args, 'year') and args.year:
                    cmd_args.extend(["--year", str(args.year)])
                if hasattr(args, 'recent_days') and args.recent_days:
                    cmd_args.extend(["--recent-days", str(args.recent_days)])
                if hasattr(args, 'start_date') and args.start_date:
                    cmd_args.extend(["--start-date", args.start_date])
                if hasattr(args, 'end_date') and args.end_date:
                    cmd_args.extend(["--end-date", args.end_date])
                if hasattr(args, 'all') and args.all:
                    cmd_args.append("--all")
                return manager.run_script("download_cves", cmd_args)
            
            elif args.command == "download-kev":
                success = manager.download_kev()
                return 0 if success else 1
            
            elif args.command == "query-database":
                manager.log("Querying database...")
                cmd_args = ["--db-path", str(manager.database_path)]
                
                # Add query subcommand and arguments
                if hasattr(args, 'query_command') and args.query_command:
                    cmd_args.append(args.query_command)
                    
                    # Add subcommand-specific arguments
                    if args.query_command == 'cve' and hasattr(args, 'cve_id'):
                        cmd_args.append(args.cve_id)
                    elif args.query_command == 'vendor' and hasattr(args, 'vendor_name'):
                        cmd_args.extend([args.vendor_name, "--limit", str(args.limit)])
                    elif args.query_command == 'product' and hasattr(args, 'product_name'):
                        cmd_args.extend([args.product_name, "--limit", str(args.limit)])
                    elif args.query_command == 'kev' and hasattr(args, 'limit'):
                        cmd_args.extend(["--limit", str(args.limit)])
                    elif args.query_command == 'years' and hasattr(args, 'years'):
                        cmd_args.extend(["--years", str(args.years)])
                    elif args.query_command == 'top-vendors' and hasattr(args, 'limit'):
                        cmd_args.extend(["--limit", str(args.limit)])
                    elif args.query_command == 'search' and hasattr(args, 'query'):
                        cmd_args.extend([args.query, "--limit", str(args.limit)])
                
                return manager.run_script("query_database", cmd_args)
            
            elif args.command in ["shell", "bash"]:
                manager.log("Starting interactive shell...")
                os.execv("/bin/bash", ["/bin/bash"])
            
            elif args.command == "init":
                manager.log("Container initialization complete")
                return 0
            
            elif args.command in ["health", "healthcheck"]:
                return manager.health_check()
            
            # For analysis commands, pass to vulnanalyzer CLI
            else:
                manager.log("Running vulnerability analysis...")
                # Set up environment for vulnanalyzer
                os.environ['CVE_DATA_PATH'] = str(manager.cve_data_path)
                os.environ['DATABASE_PATH'] = str(manager.database_path)
                os.environ['KEV_FILE_PATH'] = str(manager.kev_file_path)
                
                # Convert args back to sys.argv format for vulnanalyzer
                sys.argv = ['vulnanalyzer', args.command, args.identifier]
                if hasattr(args, 'comprehensive') and args.comprehensive:
                    sys.argv.append('--comprehensive')
                if hasattr(args, 'output_format') and args.output_format:
                    sys.argv.extend(['--output-format', args.output_format])
                if args.verbose:
                    sys.argv.append('--verbose')
                if hasattr(args, 'api_key') and args.api_key:
                    sys.argv.extend(['--api-key', args.api_key])
                
                try:
                    return vulnanalyzer_main()
                except SystemExit as e:
                    return e.code if e.code else 0
                
        except KeyboardInterrupt:
            manager.log("Interrupted by user")
            return 130
        except Exception as e:
            manager.log(f"Error: {e}")
            return 1
    
    else:
        # Direct CLI mode - pass to appropriate script
        if not args.command:
            parser.print_help()
            return 1
        
        if args.command == "create-database":
            cmd_args = [
                "--cve-dir", str(args.cve_dir),
                "--kev-file", str(args.kev_file),
                "--db-path", args.db_path
            ]
            if args.verbose:
                cmd_args.append("--verbose")
            if args.clear:
                cmd_args.append("--clear")
            if args.stats_only:
                cmd_args.append("--stats-only")
            
            script_path = Path(__file__).parent / "create_database.py"
            cmd = [sys.executable, str(script_path)] + cmd_args
            result = subprocess.run(cmd)
            return result.returncode
        
        elif args.command == "download-cves":
            cmd_args = ["--output-dir", args.output_dir]
            if args.verbose:
                cmd_args.append("--verbose")
            if args.api_key:
                cmd_args.extend(["--api-key", args.api_key])
            if args.year:
                cmd_args.extend(["--year", str(args.year)])
            if args.recent_days:
                cmd_args.extend(["--recent-days", str(args.recent_days)])
            if args.start_date:
                cmd_args.extend(["--start-date", args.start_date])
            if args.end_date:
                cmd_args.extend(["--end-date", args.end_date])
            if args.all:
                cmd_args.append("--all")
            if args.max_retries:
                cmd_args.extend(["--max-retries", str(args.max_retries)])
            if args.retry_delay:
                cmd_args.extend(["--retry-delay", str(args.retry_delay)])
            if args.max_retry_delay:
                cmd_args.extend(["--max-retry-delay", str(args.max_retry_delay)])
            
            script_path = Path(__file__).parent / "download_cves.py"
            cmd = [sys.executable, str(script_path)] + cmd_args
            result = subprocess.run(cmd)
            return result.returncode
        
        elif args.command == "query-database":
            cmd_args = ["--db-path", args.db_path]
            
            if hasattr(args, 'query_command') and args.query_command:
                cmd_args.append(args.query_command)
                
                # Add subcommand-specific arguments
                if args.query_command == 'cve':
                    cmd_args.append(args.cve_id)
                elif args.query_command == 'vendor':
                    cmd_args.extend([args.vendor_name, "--limit", str(args.limit)])
                elif args.query_command == 'product':
                    cmd_args.extend([args.product_name, "--limit", str(args.limit)])
                elif args.query_command == 'kev':
                    cmd_args.extend(["--limit", str(args.limit)])
                elif args.query_command == 'years':
                    cmd_args.extend(["--years", str(args.years)])
                elif args.query_command == 'top-vendors':
                    cmd_args.extend(["--limit", str(args.limit)])
                elif args.query_command == 'search':
                    cmd_args.extend([args.query, "--limit", str(args.limit)])
            
            script_path = Path(__file__).parent / "query_database.py"
            cmd = [sys.executable, str(script_path)] + cmd_args
            result = subprocess.run(cmd)
            return result.returncode
        
        else:
            # For analysis commands, setup, update - pass to vulnanalyzer CLI
            sys.argv = ['vulnanalyzer', args.command]
            if hasattr(args, 'identifier') and args.identifier:
                sys.argv.append(args.identifier)
            if hasattr(args, 'comprehensive') and args.comprehensive:
                sys.argv.append('--comprehensive')
            if hasattr(args, 'output_format') and args.output_format != "both":
                sys.argv.extend(['--output-format', args.output_format])
            if hasattr(args, 'days') and args.days != 30:
                sys.argv.extend(['--days', str(args.days)])
            if args.verbose:
                sys.argv.append('--verbose')
            if args.api_key:
                sys.argv.extend(['--api-key', args.api_key])
            
            try:
                return vulnanalyzer_main()
            except SystemExit as e:
                return e.code if e.code else 0


if __name__ == "__main__":
    sys.exit(main()) 