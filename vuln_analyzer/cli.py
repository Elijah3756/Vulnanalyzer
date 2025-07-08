"""CLI interface for vulnerability analysis."""

import json
import sys
from pathlib import Path
from typing import Optional

import click

from .data_processor import VulnerabilityProcessor
from .models import AnalysisResult


@click.command()
@click.argument("identifier", type=str)
@click.option(
    "--input-type",
    type=click.Choice(["cve", "purl", "cpe"], case_sensitive=False),
    help="Type of input identifier (auto-detected if not specified)",
)
@click.option(
    "--cve-data-path",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, path_type=Path),
    default="./cvelistV5/cves",
    help="Path to CVE data directory",
)
@click.option(
    "--output-format",
    type=click.Choice(["json", "pretty"], case_sensitive=False),
    default="json",
    help="Output format",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--use-database",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    help="Use SQLite database for faster queries (optional)",
)
@click.version_option()
def main(
    identifier: str,
    input_type: Optional[str],
    cve_data_path: Path,
    output_format: str,
    verbose: bool,
    use_database: Optional[Path],
) -> None:
    """
    Analyze vulnerability data for CVE, PURL, or CPE identifiers.
    
    IDENTIFIER can be:
    - CVE ID (e.g., CVE-2020-0001)
    - PURL (e.g., pkg:npm/lodash@4.17.20)
    - CPE (e.g., cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*)
    """
    try:
        # Initialize the processor
        if use_database:
            from .database import CVEDatabase
            with CVEDatabase(str(use_database)) as db:
                if verbose:
                    stats = db.get_database_stats()
                    click.echo(f"Using database with {stats['total_cves']:,} CVEs", err=True)
                
                # Detect input type if not specified
                if input_type is None:
                    # Use processor for detection
                    temp_processor = VulnerabilityProcessor(cve_data_path, verbose=verbose)
                    input_type = temp_processor.detect_input_type(identifier)
                    if verbose:
                        click.echo(f"Detected input type: {input_type}", err=True)
                
                # Analyze using database
                if input_type.lower() == "cve":
                    result = db.analyze_cve_database(identifier)
                else:
                    result = db.analyze_package_database(identifier, input_type)
        else:
            # Use file-based processor
            processor = VulnerabilityProcessor(cve_data_path, verbose=verbose)
            
            # Detect input type if not specified
            if input_type is None:
                input_type = processor.detect_input_type(identifier)
                if verbose:
                    click.echo(f"Detected input type: {input_type}", err=True)
            
            # Process the identifier
            result = processor.analyze(identifier, input_type)
        
        # Output results
        if output_format == "json":
            click.echo(json.dumps(result.to_dict(), indent=2))
        else:
            # Pretty format
            click.echo(f"Analysis Results for {identifier}")
            click.echo("=" * 50)
            click.echo(f"Input Type: {input_type.upper()}")
            click.echo(f"Matched CVEs: {len(result.matched_cves)}")
            click.echo(f"Vulnerability Introduction Rate: {result.introduction_rate:.2%}")
            click.echo(f"History Usage Rate: {result.history_usage_rate:.2%}")
            click.echo(f"Analysis Period: {result.analysis_period}")
            
            if result.matched_cves:
                click.echo("\nMatched CVEs:")
                for cve in result.matched_cves[:10]:  # Show first 10
                    click.echo(f"  - {cve}")
                if len(result.matched_cves) > 10:
                    click.echo(f"  ... and {len(result.matched_cves) - 10} more")
            
            if result.error_message:
                click.echo(f"\nWarning: {result.error_message}", err=True)
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main() 