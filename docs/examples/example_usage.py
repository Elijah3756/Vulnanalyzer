#!/usr/bin/env python3
"""Example usage of the vulnerability analyzer."""

import os
from pathlib import Path
from vulnanalyzer import VulnerabilityProcessor


def main():
    """Demonstrate how to use the vulnerability analyzer programmatically."""
    
    # Initialize the processor with environment-aware paths
    cve_data_path = Path(os.getenv('CVE_DATA_PATH', os.path.expanduser('~/.vulnanalyzer/cvelistV5/cves')))
    kev_file_path = Path(os.getenv('KEV_FILE_PATH', os.path.expanduser('~/.vulnanalyzer/known_exploited_vulnerabilities.json')))
    processor = VulnerabilityProcessor(cve_data_path, verbose=True, kev_file_path=kev_file_path)
    
    # Example 1: Analyze a CVE ID
    print("=" * 50)
    print("Example 1: Analyzing CVE-2020-0001")
    print("=" * 50)
    
    try:
        result = processor.analyze("CVE-2020-0001", "cve")
        print(f"Found {len(result.matched_cves)} related CVEs")
        print(f"Introduction Rate: {result.introduction_rate:.2%}")
        print(f"Usage Rate: {result.history_usage_rate:.2%}")
        print(f"Vendor: {result.metadata.get('vendor', 'N/A')}")
        print(f"Product: {result.metadata.get('product', 'N/A')}")
        if result.error_message:
            print(f"Warning: {result.error_message}")
    except Exception as e:
        print(f"Error analyzing CVE: {e}")
    
    # Example 2: Analyze a PURL
    print("\n" + "=" * 50)
    print("Example 2: Analyzing pkg:npm/lodash@4.17.20")
    print("=" * 50)
    
    try:
        result = processor.analyze("pkg:npm/lodash@4.17.20", "purl")
        print(f"Found {len(result.matched_cves)} related CVEs")
        print(f"Introduction Rate: {result.introduction_rate:.2%}")
        print(f"Usage Rate: {result.history_usage_rate:.2%}")
        print(f"Package: {result.metadata.get('package_name', 'N/A')}")
        print(f"Version: {result.metadata.get('package_version', 'N/A')}")
        if result.matched_cves:
            print("Sample CVEs:")
            for cve in result.matched_cves[:5]:
                print(f"  - {cve}")
    except Exception as e:
        print(f"Error analyzing PURL: {e}")
    
    # Example 3: Comprehensive PURL Analysis
    print("\n" + "=" * 60)
    print("Example 3: Comprehensive PURL Analysis - pkg:npm/express@4.17.1")
    print("=" * 60)
    
    try:
        comprehensive_result = processor.analyze_comprehensive("pkg:npm/express@4.17.1", "purl")
        print(f"Overall Analysis: {len(comprehensive_result.overall_analysis.matched_cves)} CVEs")
        print(f"Components Analyzed: {len(comprehensive_result.component_analyses)}")
        
        print("\nComponent Breakdown:")
        for comp in comprehensive_result.component_analyses:
            print(f"  {comp.component_name} ({comp.component_value}):")
            print(f"    Risk Level: {comp.get_risk_level()}")
            print(f"    CVEs Found: {len(comp.matched_cves)}")
            print(f"    Exploitation Risk: {comp.exploitation_risk:.2%}")
            print(f"    Activity Rate: {comp.vulnerability_activity_rate:.2f}")
        
        print(f"\nAggregated Metrics:")
        metrics = comprehensive_result.aggregated_metrics
        print(f"  Total Unique CVEs: {metrics.get('total_unique_cves', 0)}")
        print(f"  Average Exploitation Risk: {metrics.get('average_exploitation_risk', 0):.2%}")
        print(f"  Highest Risk Component: {metrics.get('highest_risk_component_name', 'N/A')}")
        
        print(f"\nTop Recommendations:")
        for i, rec in enumerate(comprehensive_result.recommendations[:3], 1):
            print(f"  {i}. {rec}")
            
    except Exception as e:
        print(f"Error with comprehensive PURL analysis: {e}")
    
    # Example 4: Analyze a CPE
    print("\n" + "=" * 50)
    print("Example 4: Analyzing cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*")
    print("=" * 50)
    
    try:
        result = processor.analyze("cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*", "cpe")
        print(f"Found {len(result.matched_cves)} related CVEs")
        print(f"Introduction Rate: {result.introduction_rate:.2%}")
        print(f"Usage Rate: {result.history_usage_rate:.2%}")
        print(f"Vendor: {result.metadata.get('vendor', 'N/A')}")
        print(f"Product: {result.metadata.get('product', 'N/A')}")
        if result.matched_cves:
            print("Sample CVEs:")
            for cve in result.matched_cves[:5]:
                print(f"  - {cve}")
    except Exception as e:
        print(f"Error analyzing CPE: {e}")
    
    # Example 5: Comprehensive CPE Analysis
    print("\n" + "=" * 60)
    print("Example 5: Comprehensive CPE Analysis - cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
    print("=" * 60)
    
    try:
        comprehensive_result = processor.analyze_comprehensive("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*", "cpe")
        print(f"Overall Analysis: {len(comprehensive_result.overall_analysis.matched_cves)} CVEs")
        print(f"Components Analyzed: {len(comprehensive_result.component_analyses)}")
        
        print("\nComponent Breakdown:")
        for comp in comprehensive_result.component_analyses:
            print(f"  {comp.component_name} ({comp.component_value}):")
            print(f"    Risk Level: {comp.get_risk_level()}")
            print(f"    CVEs Found: {len(comp.matched_cves)}")
            print(f"    Exploitation Risk: {comp.exploitation_risk:.2%}")
            print(f"    Activity Rate: {comp.vulnerability_activity_rate:.2f}")
        
        print(f"\nAggregated Metrics:")
        metrics = comprehensive_result.aggregated_metrics
        print(f"  Total Unique CVEs: {metrics.get('total_unique_cves', 0)}")
        print(f"  Average Exploitation Risk: {metrics.get('average_exploitation_risk', 0):.2%}")
        print(f"  Highest Risk Component: {metrics.get('highest_risk_component_name', 'N/A')}")
        print(f"  Most Active Component: {metrics.get('most_active_component_name', 'N/A')}")
        
        print(f"\nTop Recommendations:")
        for i, rec in enumerate(comprehensive_result.recommendations[:3], 1):
            print(f"  {i}. {rec}")
            
    except Exception as e:
        print(f"Error with comprehensive CPE analysis: {e}")
    
    # Example 6: Auto-detect input type
    print("\n" + "=" * 50)
    print("Example 6: Auto-detecting input type")
    print("=" * 50)
    
    test_inputs = [
        "CVE-2021-44228",  # Log4Shell
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
    ]
    
    for test_input in test_inputs:
        try:
            detected_type = processor.detect_input_type(test_input)
            print(f"Input: {test_input}")
            print(f"Detected type: {detected_type}")
            
            result = processor.analyze(test_input, detected_type)
            print(f"  -> Found {len(result.matched_cves)} CVEs")
            print(f"  -> Introduction Rate: {result.introduction_rate:.2%}")
            print()
        except Exception as e:
            print(f"Error with {test_input}: {e}")
            print()
    
    # Example 7: Wildcard Comprehensive Analysis for "python"
    print("\n" + "=" * 60)
    print("Example 7: Wildcard Analysis - 'python'")
    print("=" * 60)
    
    try:
        wildcard_result = processor.analyze_wildcard("python")
        print(f"Search Term: {wildcard_result.search_term}")
        print(f"Total Matched CVEs: {len(wildcard_result.total_matched_cves)}")
        print(f"Categories Found: {len(wildcard_result.category_analyses)}")
        
        if wildcard_result.overall_metrics:
            metrics = wildcard_result.overall_metrics
            print(f"\nOverall Metrics:")
            print(f"  Recent CVEs (2020-2025): {metrics.get('recent_cves', 0)}")
            print(f"  Historical CVEs (pre-2020): {metrics.get('historical_cves', 0)}")
            print(f"  Known Exploited CVEs: {metrics.get('known_exploited_cves', 0)}")
            print(f"  Vulnerability Activity Rate: {metrics.get('vulnerability_activity_rate', 0):.2f}")
            print(f"  Exploitation Risk: {metrics.get('exploitation_risk', 0):.2%}")
        
        print(f"\nCategory Breakdown:")
        for cat in wildcard_result.category_analyses:
            print(f"  {cat.category_name}: {cat.total_cves} CVEs, {cat.unique_matches} unique matches")
            print(f"    Exploitation Risk: {cat.exploitation_risk:.2%}")
            if cat.top_matches:
                top_match = cat.top_matches[0]
                print(f"    Top Match: '{top_match[0]}' ({top_match[1]} CVEs)")
        
        print(f"\nTop Recommendations:")
        for i, rec in enumerate(wildcard_result.recommendations[:5], 1):
            print(f"  {i}. {rec}")
            
    except Exception as e:
        print(f"Error with wildcard analysis for 'python': {e}")
    
    # Example 8: Wildcard Analysis for "apache *"
    print("\n" + "=" * 60)
    print("Example 8: Wildcard Analysis - 'apache *'")
    print("=" * 60)
    
    try:
        wildcard_result = processor.analyze_wildcard("apache *")
        print(f"Search Term: {wildcard_result.search_term}")
        print(f"Total Matched CVEs: {len(wildcard_result.total_matched_cves)}")
        
        if wildcard_result.temporal_analysis:
            temporal = wildcard_result.temporal_analysis
            print(f"\nTemporal Analysis:")
            print(f"  Trend: {temporal.get('trend', 'unknown').upper()}")
            print(f"  Peak Year: {temporal.get('peak_year', 'N/A')} ({temporal.get('peak_year_count', 0)} CVEs)")
        
        print(f"\nCategory Summary:")
        for cat in wildcard_result.category_analyses[:3]:  # Top 3 categories
            print(f"  {cat.category_name}: {cat.total_cves} CVEs, Risk: {cat.exploitation_risk:.2%}")
        
        print(f"\nSample CVEs:")
        for cve in wildcard_result.total_matched_cves[:10]:
            print(f"  - {cve}")
        if len(wildcard_result.total_matched_cves) > 10:
            print(f"  ... and {len(wildcard_result.total_matched_cves) - 10} more")
            
    except Exception as e:
        print(f"Error with wildcard analysis for 'apache *': {e}")
    
    # Example 9: Auto-detect wildcard input
    print("\n" + "=" * 60)
    print("Example 9: Auto-detecting wildcard inputs")
    print("=" * 60)
    
    wildcard_test_inputs = [
        "nodejs",  # Single term
        "microsoft *",  # Explicit wildcard
        "openssl",  # Another single term
    ]
    
    for test_input in wildcard_test_inputs:
        try:
            detected_type = processor.detect_input_type(test_input)
            print(f"Input: '{test_input}' -> Type: {detected_type}")
            
            if detected_type == "wildcard":
                result = processor.analyze_wildcard(test_input)
                print(f"  Found {len(result.total_matched_cves)} CVEs across {len(result.category_analyses)} categories")
                if result.overall_metrics:
                    print(f"  Overall Exploitation Risk: {result.overall_metrics.get('exploitation_risk', 0):.2%}")
            else:
                result = processor.analyze(test_input, detected_type)
                print(f"  Found {len(result.matched_cves)} CVEs")
            print()
        except Exception as e:
            print(f"Error with '{test_input}': {e}")
            print()


if __name__ == "__main__":
    main() 