#!/usr/bin/env python3
"""
Professional vulnerability analysis CLI tool.

Usage:
    vulnanalyzer cve CVE-2021-44228
    vulnanalyzer purl "pkg:npm/lodash@4.17.20"
    vulnanalyzer cpe "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*"
    vulnanalyzer wildcard "python"
    vulnanalyzer -setup
    vulnanalyzer -update
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Optional, Dict, Any

from .data_processor import VulnerabilityProcessor
from .database_manager import DatabaseManager
from .models import AnalysisResult


def get_default_paths() -> Dict[str, Path]:
    """Get default paths for data and configuration."""
    home_dir = Path.home()
    data_dir = Path(os.getenv('VULNANALYZER_DATA', home_dir / '.vulnanalyzer'))
    
    return {
        'data_dir': data_dir,
        'cve_data_path': data_dir / 'cvelistV5' / 'cves',
        'database_path': data_dir / 'databases' / 'cve_database.db',
        'kev_file_path': data_dir / 'known_exploited_vulnerabilities_catalog.json',
        'download_dir': data_dir / 'downloads'
    }


def setup_directories(paths: Dict[str, Path]) -> None:
    """Create necessary directories if they don't exist."""
    # Only create directories for paths that should be directories
    directories_to_create = [
        paths['data_dir'],
        paths['cve_data_path'], 
        paths['database_path'].parent,  # parent directory of database file
        paths['download_dir'],
        paths['kev_file_path'].parent   # parent directory of KEV file
    ]
    
    for path in directories_to_create:
        if isinstance(path, Path):
            path.mkdir(parents=True, exist_ok=True)


def print_analysis_result(result: AnalysisResult, output_format: str = "both") -> None:
    """Print analysis results in the specified format."""
    if output_format in ["text", "both"]:
        print_text_output(result)
    
    if output_format in ["json", "both"]:
        print_json_output(result)


def print_text_output(result: AnalysisResult) -> None:
    """Print analysis results in human-readable text format."""
    print("=" * 80)
    print(f"VULNERABILITY ANALYSIS RESULTS")
    print("=" * 80)
    print(f"Identifier: {result.identifier}")
    print(f"Type: {result.input_type.upper()}")
    print(f"Analysis Period: {result.analysis_period}")
    print(f"Total CVEs Analyzed: {result.total_cves_analyzed:,}")
    print(f"Matched CVEs: {len(result.matched_cves):,}")
    
    print("\n" + "-" * 40)
    print("RISK METRICS")
    print("-" * 40)
    
    # Legacy metrics
    print(f"Introduction Rate: {result.introduction_rate:.2%}")
    print(f"History Usage Rate: {result.history_usage_rate:.2%}")
    
    # Enhanced metrics
    if result.vulnerability_activity_rate is not None:
        print(f"Vulnerability Activity Rate: {result.vulnerability_activity_rate:.2f}")
        print(f"  Interpretation: {result._interpret_activity_rate()}")
    
    if result.exploitation_risk is not None:
        print(f"Exploitation Risk: {result.exploitation_risk:.2%}")
        print(f"  Interpretation: {result._interpret_exploitation_risk()}")
    
    if result.relative_threat_level is not None:
        print(f"Relative Threat Level: {result.relative_threat_level:.3%}")
        print(f"  Interpretation: {result._interpret_threat_level()}")
    
    # Metadata
    if result.metadata:
        print("\n" + "-" * 40)
        print("DETAILED INFORMATION")
        print("-" * 40)
        
        if 'vendor' in result.metadata:
            print(f"Vendor: {result.metadata['vendor']}")
        if 'product' in result.metadata:
            print(f"Product: {result.metadata['product']}")
        if 'package_name' in result.metadata:
            print(f"Package: {result.metadata['package_name']}")
        if 'package_version' in result.metadata:
            print(f"Version: {result.metadata['package_version']}")
        
        # Risk summary if available
        if 'risk_summary' in result.metadata:
            risk_summary = result.metadata['risk_summary']
            print("\nRisk Summary:")
            
            if 'vulnerability_activity' in risk_summary:
                activity = risk_summary['vulnerability_activity']
                print(f"  Recent CVEs (2020-2025): {activity.get('recent_cves', 0):,}")
                print(f"  Historical CVEs (pre-2020): {activity.get('historical_cves', 0):,}")
            
            if 'exploitation_risk' in risk_summary:
                exploitation = risk_summary['exploitation_risk']
                print(f"  Known Exploited CVEs: {exploitation.get('exploited_cves', 0):,}")
                print(f"  Total Component CVEs: {exploitation.get('total_cves', 0):,}")
    
    # Sample CVEs
    if result.matched_cves:
        print(f"\n" + "-" * 40)
        print("SAMPLE MATCHED CVEs")
        print("-" * 40)
        sample_size = min(10, len(result.matched_cves))
        for i, cve in enumerate(result.matched_cves[:sample_size], 1):
            print(f"{i:2d}. {cve}")
        
        if len(result.matched_cves) > sample_size:
            print(f"     ... and {len(result.matched_cves) - sample_size:,} more")
    
    # Error messages
    if result.error_message:
        print(f"\n" + "-" * 40)
        print("WARNINGS")
        print("-" * 40)
        print(f"Warning: {result.error_message}")
    
    print("=" * 80)


def print_json_output(result: AnalysisResult) -> None:
    """Print analysis results in JSON format."""
    print("\n" + "=" * 80)
    print("JSON OUTPUT")
    print("=" * 80)
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    print("=" * 80)


def handle_setup_command(args: argparse.Namespace) -> None:
    """Handle the setup command to create database with all CVEs and KEVs."""
    print("Initializing vulnerability analyzer database...")
    
    paths = get_default_paths()
    setup_directories(paths)
    
    db_manager = DatabaseManager(
        database_path=paths['database_path'],
        cve_data_path=paths['cve_data_path'],
        kev_file_path=paths['kev_file_path'],
        download_dir=paths['download_dir'],
        verbose=args.verbose
    )
    
    try:
        print("Downloading CISA Known Exploited Vulnerabilities...")
        db_manager.download_kev_data()
        
        print("Downloading CVE data from NVD...")
        if args.api_key:
            print("Using provided API key for faster downloads")
            db_manager.download_cve_data(api_key=args.api_key, all_cves=True)
        else:
            print("No API key provided. Downloads will be slower.")
            print("Get a free API key from: https://nvd.nist.gov/developers/request-an-api-key")
            db_manager.download_cve_data(all_cves=True)
        
        print("Building vulnerability database...")
        db_manager.create_database()
        
        print("Setup completed successfully!")
        
        # Show database statistics
        stats = db_manager.get_database_stats()
        print(f"\nDatabase Statistics:")
        print(f"  Total CVEs: {stats['total_cves']:,}")
        print(f"  Known Exploited: {stats['known_exploited']:,}")
        print(f"  Database Size: {stats['db_size_mb']} MB")
    
    except Exception as e:
        print(f"Setup failed: {str(e)}")
        sys.exit(1)


def handle_update_command(args: argparse.Namespace) -> None:
    """Handle the update command to pull recent data."""
    print("Updating vulnerability data...")
    
    paths = get_default_paths()
    setup_directories(paths)
    
    db_manager = DatabaseManager(
        database_path=paths['database_path'],
        cve_data_path=paths['cve_data_path'],
        kev_file_path=paths['kev_file_path'],
        download_dir=paths['download_dir'],
        verbose=args.verbose
    )
    
    try:
        print("Downloading latest CISA Known Exploited Vulnerabilities...")
        db_manager.download_kev_data()
        
        print("Downloading recent CVE data...")
        if args.api_key:
            db_manager.download_cve_data(api_key=args.api_key, recent_days=args.days)
        else:
            db_manager.download_cve_data(recent_days=args.days)
        
        print("Updating database...")
        db_manager.update_database()
        
        print("Update completed successfully!")
        
        # Show updated statistics
        stats = db_manager.get_database_stats()
        print(f"\nUpdated Database Statistics:")
        print(f"  Total CVEs: {stats['total_cves']:,}")
        print(f"  Known Exploited: {stats['known_exploited']:,}")
        
    except Exception as e:
        print(f"Update failed: {str(e)}")
        sys.exit(1)


def handle_analysis_command(args: argparse.Namespace) -> None:
    """Handle vulnerability analysis commands."""
    paths = get_default_paths()
    setup_directories(paths)
    
    # Initialize processor
    processor = VulnerabilityProcessor(
        cve_data_path=paths['cve_data_path'],
        verbose=args.verbose,
        kev_file_path=paths['kev_file_path']
    )
    
    try:
        # Detect input type if not specified
        if not args.type:
            args.type = processor.detect_input_type(args.identifier)
        
        print(f"Analyzing {args.type.upper()}: {args.identifier}")
        
        # Perform analysis based on type
        if args.type.lower() == "wildcard":
            result = processor.analyze_wildcard(args.identifier)
            # Convert to standard AnalysisResult for output
            result = processor._convert_wildcard_to_analysis(result)
        elif args.comprehensive and args.type.lower() in ["purl", "cpe"]:
            comprehensive_result = processor.analyze_comprehensive(args.identifier, args.type)
            result = comprehensive_result.overall_analysis
        else:
            result = processor.analyze(args.identifier, args.type)
        
        # Print results
        print_analysis_result(result, args.output_format)
        
    except Exception as e:
        print(f"Analysis failed: {str(e)}")
        sys.exit(1)


def main() -> None:
    """Main CLI entry point."""
    # Parse arguments from sys.argv - this assumes arguments are already parsed by main.py
    if len(sys.argv) < 2:
        print("Error: No command specified")
        sys.exit(1)
    
    # Create a simple namespace from command line arguments
    class Args:
        def __init__(self):
            self.command = sys.argv[1] if len(sys.argv) > 1 else None
            self.identifier = sys.argv[2] if len(sys.argv) > 2 else None
            self.verbose = "--verbose" in sys.argv or "-v" in sys.argv
            self.api_key = None
            self.comprehensive = "--comprehensive" in sys.argv
            self.days = 30
            self.output_format = "both"
            self.type = None  # Add type attribute for compatibility
            
            # Extract API key if present
            if "--api-key" in sys.argv:
                try:
                    api_key_index = sys.argv.index("--api-key")
                    if api_key_index + 1 < len(sys.argv):
                        self.api_key = sys.argv[api_key_index + 1]
                except (ValueError, IndexError):
                    pass
            
            # Extract output format if present
            if "--output-format" in sys.argv:
                try:
                    format_index = sys.argv.index("--output-format")
                    if format_index + 1 < len(sys.argv):
                        self.output_format = sys.argv[format_index + 1]
                except (ValueError, IndexError):
                    pass
            
            # Extract days if present
            if "--days" in sys.argv:
                try:
                    days_index = sys.argv.index("--days")
                    if days_index + 1 < len(sys.argv):
                        self.days = int(sys.argv[days_index + 1])
                except (ValueError, IndexError):
                    pass
    
    args = Args()
    
    # Handle different commands
    if args.command == "setup":
        handle_setup_command(args)
    elif args.command == "update":
        handle_update_command(args)
    elif args.command in ["cve", "purl", "cpe", "wildcard"]:
        handle_analysis_command(args)
    else:
        print(f"Error: Unknown command '{args.command}'")
        sys.exit(1)

