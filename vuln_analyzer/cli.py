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
@click.option(
    "--kev-file",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, path_type=Path),
    default="known_exploited_vulnerabilities.json",
    help="Path to known exploited vulnerabilities JSON file",
)
@click.option(
    "--comprehensive",
    "-c",
    is_flag=True,
    help="Perform comprehensive component analysis (for PURL, CPE, and wildcard searches)",
)
@click.version_option()
def main(
    identifier: str,
    input_type: Optional[str],
    cve_data_path: Path,
    output_format: str,
    verbose: bool,
    use_database: Optional[Path],
    kev_file: Optional[Path],
    comprehensive: bool,
) -> None:
    """
    Analyze vulnerability data for CVE, PURL, CPE identifiers, or perform wildcard searches.
    
    IDENTIFIER can be:
    - CVE ID (e.g., CVE-2020-0001)
    - PURL (e.g., pkg:npm/lodash@4.17.20)
    - CPE (e.g., cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*)
    - Wildcard search (e.g., python, "python *", nodejs, apache)
    
    Use --comprehensive flag for detailed component analysis of PURLs, CPEs, and wildcard searches.
    
    Wildcard searches will comprehensively analyze all database entries related to the search term,
    including vendors, products, descriptions, and vulnerability classifications.
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
                    temp_processor = VulnerabilityProcessor(cve_data_path, verbose=verbose, kev_file_path=kev_file)
                    input_type = temp_processor.detect_input_type(identifier)
                    if verbose:
                        click.echo(f"Detected input type: {input_type}", err=True)
                
                # For comprehensive analysis with database, fall back to file-based for now
                if comprehensive and input_type.lower() in ["purl", "cpe", "wildcard"]:
                    if verbose:
                        click.echo("Comprehensive analysis requires file-based processing, switching to file mode", err=True)
                    processor = VulnerabilityProcessor(cve_data_path, verbose=verbose, kev_file_path=kev_file)
                    if input_type.lower() == "wildcard":
                        result = processor.analyze_wildcard(identifier)
                    else:
                        result = processor.analyze_comprehensive(identifier, input_type)
                else:
                    # Regular database analysis
                    if input_type.lower() == "cve":
                        result = db.analyze_cve_database(identifier)
                    elif input_type.lower() == "wildcard":
                        result = db.analyze_wildcard_database(identifier)
                    else:
                        result = db.analyze_package_database(identifier, input_type)
        else:
            # Use file-based processor
            processor = VulnerabilityProcessor(cve_data_path, verbose=verbose, kev_file_path=kev_file)
            
            # Detect input type if not specified
            if input_type is None:
                input_type = processor.detect_input_type(identifier)
                if verbose:
                    click.echo(f"Detected input type: {input_type}", err=True)
            
            # Process the identifier
            if comprehensive and input_type.lower() in ["purl", "cpe"]:
                result = processor.analyze_comprehensive(identifier, input_type)
            elif comprehensive and input_type.lower() == "wildcard":
                result = processor.analyze_wildcard(identifier)
            elif input_type.lower() == "wildcard":
                result = processor.analyze_wildcard(identifier)
            else:
                result = processor.analyze(identifier, input_type)
        
        # Output results
        if output_format == "json":
            if hasattr(result, 'to_dict'):
                click.echo(json.dumps(result.to_dict(), indent=2))
            else:
                click.echo(json.dumps(result.to_dict(), indent=2))  # AnalysisResult
        else:
            # Pretty format - check result type
            if hasattr(result, 'category_analyses'):  # WildcardAnalysisResult
                _display_wildcard_results(result)
            elif hasattr(result, 'component_analyses'):  # ComprehensiveAnalysisResult
                _display_comprehensive_results(result)
            else:  # AnalysisResult
                _display_regular_results(result, input_type)
    
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


def _display_comprehensive_results(result) -> None:
    """Display comprehensive analysis results in pretty format."""
    click.echo(f"Comprehensive Analysis Results for {result.identifier}")
    click.echo("=" * 70)
    click.echo(f"Input Type: {result.input_type.upper()}")
    click.echo(f"Components Analyzed: {len(result.component_analyses)}")
    
    # Overall Analysis Summary
    overall = result.overall_analysis
    click.echo(f"\nOverall Analysis:")
    click.echo(f"  Total Matched CVEs: {len(overall.matched_cves)}")
    if overall.vulnerability_activity_rate is not None:
        click.echo(f"  Overall Activity Rate: {overall.vulnerability_activity_rate:.2f}")
        click.echo(f"  Overall Exploitation Risk: {overall.exploitation_risk:.2%}")
        click.echo(f"  Overall Threat Level: {overall.relative_threat_level:.3%}")
    
    # Component Analysis
    if result.component_analyses:
        click.echo(f"\nComponent-by-Component Analysis:")
        click.echo("-" * 50)
        
        for i, comp in enumerate(result.component_analyses, 1):
            risk_level = comp.get_risk_level()
            risk_color = {
                "CRITICAL": "red",
                "HIGH": "red", 
                "MEDIUM": "yellow",
                "LOW": "green",
                "VERY_LOW": "green"
            }.get(risk_level, "white")
            
            click.echo(f"\n{i}. {comp.component_name}: {comp.component_value}")
            click.echo(f"   Risk Level: ", nl=False)
            click.secho(f"{risk_level}", fg=risk_color, bold=True)
            click.echo(f"   Matched CVEs: {len(comp.matched_cves)}")
            click.echo(f"   Exploitation Risk: {comp.exploitation_risk:.2%}")
            click.echo(f"   Activity Rate: {comp.vulnerability_activity_rate:.2f}")
            click.echo(f"   Threat Level: {comp.relative_threat_level:.3%}")
            
            # Show top CVEs if any
            if comp.matched_cves:
                click.echo(f"   Top CVEs: {', '.join(comp.matched_cves[:5])}")
                if len(comp.matched_cves) > 5:
                    click.echo(f"             ... and {len(comp.matched_cves) - 5} more")
    
    # Aggregated Metrics
    if result.aggregated_metrics:
        click.echo(f"\nAggregated Metrics:")
        click.echo("-" * 30)
        metrics = result.aggregated_metrics
        click.echo(f"  Components Analyzed: {metrics.get('components_analyzed', 0)}")
        click.echo(f"  Total Unique CVEs: {metrics.get('total_unique_cves', 0)}")
        click.echo(f"  Average Exploitation Risk: {metrics.get('average_exploitation_risk', 0):.2%}")
        click.echo(f"  Average Activity Rate: {metrics.get('average_activity_rate', 0):.2f}")
        click.echo(f"  Highest Risk Component: {metrics.get('highest_risk_component_name', 'N/A')}")
        click.echo(f"  Most Active Component: {metrics.get('most_active_component_name', 'N/A')}")
    
    # Security Recommendations
    if result.recommendations:
        click.echo(f"\nSecurity Recommendations:")
        click.echo("=" * 40)
        for i, rec in enumerate(result.recommendations, 1):
            if rec.startswith("CRITICAL"):
                click.secho(f"{i}. {rec}", fg="red", bold=True)
            elif rec.startswith("HIGH"):
                click.secho(f"{i}. {rec}", fg="red")
            elif rec.startswith("MEDIUM"):
                click.secho(f"{i}. {rec}", fg="yellow")
            else:
                click.echo(f"{i}. {rec}")
    
    # Error handling
    if overall.error_message:
        click.echo(f"\nWarning: {overall.error_message}", err=True)


def _display_regular_results(result, input_type: str) -> None:
    """Display regular analysis results in pretty format."""
    # Enhanced pretty format
    click.echo(f"Analysis Results for {result.identifier}")
    click.echo("=" * 60)
    click.echo(f"Input Type: {input_type.upper()}")
    click.echo(f"Matched CVEs: {len(result.matched_cves)}")
    click.echo(f"Analysis Period: {result.analysis_period}")
    
    # Legacy metrics (for backward compatibility)
    click.echo(f"\nLegacy Metrics:")
    click.echo(f"  Introduction Rate: {result.introduction_rate:.2%}")
    click.echo(f"  History Usage Rate: {result.history_usage_rate:.2%}")
    
    # Enhanced metrics (if available)
    if result.vulnerability_activity_rate is not None:
        click.echo(f"\nEnhanced Risk Assessment:")
        click.echo(f"  Vulnerability Activity Rate: {result.vulnerability_activity_rate:.2f}")
        click.echo(f"    {result._interpret_activity_rate()}")
        
    if result.exploitation_risk is not None:
        click.echo(f"  Exploitation Risk: {result.exploitation_risk:.2%}")
        click.echo(f"    {result._interpret_exploitation_risk()}")
        
    if result.relative_threat_level is not None:
        click.echo(f"  Relative Threat Level: {result.relative_threat_level:.3%}")
        click.echo(f"    {result._interpret_threat_level()}")
    
    # Risk Summary (if available in metadata)
    if result.metadata and "risk_summary" in result.metadata:
        risk_summary = result.metadata["risk_summary"]
        click.echo(f"\nDetailed Risk Analysis:")
        
        # Vulnerability Activity
        activity = risk_summary.get("vulnerability_activity", {})
        if activity:
            click.echo(f"  Activity Analysis:")
            click.echo(f"    Recent CVEs (2020-2025): {activity.get('recent_cves', 0)}")
            click.echo(f"    Historical CVEs (pre-2020): {activity.get('historical_cves', 0)}")
            click.echo(f"    Interpretation: {activity.get('interpretation', 'N/A')}")
        
        # Exploitation Risk
        exploitation = risk_summary.get("exploitation_risk", {})
        if exploitation:
            click.echo(f"  Exploitation Analysis:")
            click.echo(f"    Known Exploited CVEs: {exploitation.get('exploited_cves', 0)}")
            click.echo(f"    Total Component CVEs: {exploitation.get('total_cves', 0)}")
            click.echo(f"    Interpretation: {exploitation.get('interpretation', 'N/A')}")
        
        # Threat Level
        threat = risk_summary.get("threat_level", {})
        if threat:
            click.echo(f"  Threat Level Analysis:")
            click.echo(f"    Component Threats: {threat.get('component_threats', 0)}")
            click.echo(f"    Total Global Threats: {threat.get('total_threats', 0)}")
            click.echo(f"    Interpretation: {threat.get('interpretation', 'N/A')}")
    
    # Show CVE samples
    if result.matched_cves:
        click.echo(f"\nMatched CVEs (showing first 10 of {len(result.matched_cves)}):")
        for cve in result.matched_cves[:10]:
            click.echo(f"  - {cve}")
        if len(result.matched_cves) > 10:
            click.echo(f"  ... and {len(result.matched_cves) - 10} more")
    
    # Show any warnings
    if result.error_message:
        click.echo(f"\nWarning: {result.error_message}", err=True)


def _display_wildcard_results(result) -> None:
    """Display wildcard analysis results in pretty format."""
    click.echo(f"Comprehensive Wildcard Analysis Results for '{result.search_term}'")
    click.echo("=" * 80)
    click.echo(f"Search Term: {result.search_term}")
    click.echo(f"Total Matched CVEs: {len(result.total_matched_cves)}")
    click.echo(f"Categories Found: {len(result.category_analyses)}")
    
    # Overall metrics
    if result.overall_metrics:
        metrics = result.overall_metrics
        click.echo(f"\nOverall Analysis:")
        click.echo(f"  Recent CVEs (2020-2025): {metrics.get('recent_cves', 0)}")
        click.echo(f"  Historical CVEs (pre-2020): {metrics.get('historical_cves', 0)}")
        click.echo(f"  Known Exploited CVEs: {metrics.get('known_exploited_cves', 0)}")
        click.echo(f"  Vulnerability Activity Rate: {metrics.get('vulnerability_activity_rate', 0):.2f}")
        click.echo(f"  Exploitation Risk: {metrics.get('exploitation_risk', 0):.2%}")
        click.echo(f"  Database Coverage: {metrics.get('database_coverage', 0):.2%}")
    
    # Temporal analysis
    if result.temporal_analysis:
        temporal = result.temporal_analysis
        click.echo(f"\nTemporal Analysis:")
        click.echo(f"  Trend: {temporal.get('trend', 'unknown').upper()}")
        click.echo(f"  Recent 5 Years: {temporal.get('recent_5_years', 0)} CVEs")
        click.echo(f"  Previous 5 Years: {temporal.get('previous_5_years', 0)} CVEs")
        click.echo(f"  Peak Year: {temporal.get('peak_year', 'N/A')} ({temporal.get('peak_year_count', 0)} CVEs)")
    
    # Category breakdown
    if result.category_analyses:
        click.echo(f"\nCategory Breakdown:")
        click.echo("-" * 60)
        
        for i, cat in enumerate(result.category_analyses, 1):
            risk_level = "HIGH" if cat.exploitation_risk >= 0.10 else "MEDIUM" if cat.exploitation_risk >= 0.05 else "LOW"
            risk_color = {"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(risk_level, "white")
            
            click.echo(f"\n{i}. {cat.category_name.upper()}")
            click.echo(f"   Total CVEs: {cat.total_cves}")
            click.echo(f"   Unique Matches: {cat.unique_matches}")
            click.echo(f"   Activity Rate: {cat.vulnerability_activity_rate:.2f}")
            click.echo(f"   Exploitation Risk: ", nl=False)
            click.secho(f"{cat.exploitation_risk:.2%} ({risk_level})", fg=risk_color, bold=True)
            
            # Show top matches
            if cat.top_matches:
                click.echo(f"   Top Matches:")
                for match_value, count in cat.top_matches[:5]:
                    # Truncate long match values
                    display_value = match_value[:50] + "..." if len(match_value) > 50 else match_value
                    click.echo(f"     • {display_value}: {count} CVEs")
    
    # Recommendations
    if result.recommendations:
        click.echo(f"\nSecurity Recommendations:")
        click.echo("=" * 50)
        for i, rec in enumerate(result.recommendations, 1):
            if rec.startswith("CRITICAL"):
                click.secho(f"{i}. {rec}", fg="red", bold=True)
            elif rec.startswith("HIGH"):
                click.secho(f"{i}. {rec}", fg="red")
            elif rec.startswith("MEDIUM"):
                click.secho(f"{i}. {rec}", fg="yellow")
            else:
                click.echo(f"{i}. {rec}")
    
    # Sample CVEs
    if result.total_matched_cves:
        click.echo(f"\nSample CVEs (showing first 15 of {len(result.total_matched_cves)}):")
        for cve in result.total_matched_cves[:15]:
            click.echo(f"  - {cve}")
        if len(result.total_matched_cves) > 15:
            click.echo(f"  ... and {len(result.total_matched_cves) - 15} more")
    
    # Error handling
    if result.error_message:
        click.echo(f"\nWarning: {result.error_message}", err=True)


if __name__ == "__main__":
    main() 