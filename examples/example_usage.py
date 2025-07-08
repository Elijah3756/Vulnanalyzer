#!/usr/bin/env python3
"""Example usage of the vulnerability analyzer."""

from pathlib import Path
from vuln_analyzer.data_processor import VulnerabilityProcessor


def main():
    """Demonstrate how to use the vulnerability analyzer programmatically."""
    
    # Initialize the processor
    cve_data_path = Path("./cvelistV5/cves")
    processor = VulnerabilityProcessor(cve_data_path, verbose=True)
    
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
    
    # Example 3: Analyze a CPE
    print("\n" + "=" * 50)
    print("Example 3: Analyzing cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*")
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
    
    # Example 4: Auto-detect input type
    print("\n" + "=" * 50)
    print("Example 4: Auto-detecting input type")
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


if __name__ == "__main__":
    main() 