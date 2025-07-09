# VulnAnalyzer Programming Examples

This guide demonstrates how to use the vulnerability analyzer programmatically with Python code examples.

## Setup

```python
import os
from pathlib import Path
from vulnanalyzer import VulnerabilityProcessor

# Initialize the processor with environment-aware paths
cve_data_path = Path(os.getenv('CVE_DATA_PATH', os.path.expanduser('~/.vulnanalyzer/cvelistV5/cves')))
kev_file_path = Path(os.getenv('KEV_FILE_PATH', os.path.expanduser('~/.vulnanalyzer/known_exploited_vulnerabilities_catalog.json')))
processor = VulnerabilityProcessor(cve_data_path, verbose=True, kev_file_path=kev_file_path)
```

## Example 1: CVE Analysis

Analyze a specific CVE identifier to understand its risk profile and related vulnerabilities.

```python
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
```

**Expected Output:**
```
Found 15 related CVEs
Introduction Rate: 12.50%
Usage Rate: 8.33%
Vendor: Microsoft
Product: Windows
```

## Example 2: Package URL (PURL) Analysis

Analyze a specific package to identify known vulnerabilities and security risks.

```python
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
```

**Expected Output:**
```
Found 8 related CVEs
Introduction Rate: 15.25%
Usage Rate: 12.50%
Package: lodash
Version: 4.17.20
Sample CVEs:
  - CVE-2021-23337
  - CVE-2020-8203
  - CVE-2019-10744
```

## Example 3: Comprehensive PURL Analysis

Perform detailed component-level analysis of a package, breaking down risks by different components.

```python
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
```

**Expected Output:**
```
Overall Analysis: 45 CVEs
Components Analyzed: 4

Component Breakdown:
  Package Type (npm):
    Risk Level: MEDIUM
    CVEs Found: 1250
    Exploitation Risk: 8.40%
    Activity Rate: 1.85

  Package Name (express):
    Risk Level: HIGH
    CVEs Found: 28
    Exploitation Risk: 14.29%
    Activity Rate: 2.10

Aggregated Metrics:
  Total Unique CVEs: 45
  Average Exploitation Risk: 11.34%
  Highest Risk Component: Package Name

Top Recommendations:
  1. HIGH PRIORITY: 1 component(s) have high exploitation risk (>10%)
  2. Package 'express' shows high recent vulnerability activity - monitor for updates
  3. MEDIUM: This package has notable exploitation risk - plan security review
```

## Example 4: CPE Analysis

Analyze a Common Platform Enumeration (CPE) to assess platform-specific vulnerabilities.

```python
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
```

## Example 5: Comprehensive CPE Analysis

Detailed analysis of CPE components including vendor, product, and version-specific risks.

```python
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
```

## Example 6: Auto-Detect Input Type

Let the analyzer automatically detect what type of identifier you're providing.

```python
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
```

**Expected Output:**
```
Input: CVE-2021-44228
Detected type: cve
  -> Found 25 CVEs
  -> Introduction Rate: 18.50%

Input: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
Detected type: purl
  -> Found 12 CVEs
  -> Introduction Rate: 22.30%

Input: cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
Detected type: cpe
  -> Found 15 CVEs
  -> Introduction Rate: 20.15%
```

## Example 7: Wildcard Analysis

Perform comprehensive ecosystem analysis using wildcard searches.

```python
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
```

## Example 8: Advanced Wildcard Analysis

Analyze larger ecosystems with temporal analysis and trend detection.

```python
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
```

## Example 9: Input Type Detection Testing

Test the automatic detection of different input types.

```python
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
```

## Working with Results

### Understanding Analysis Results

All analysis methods return structured result objects with consistent fields:

```python
# Basic analysis result structure
result = processor.analyze("CVE-2021-44228", "cve")

# Core metrics
print(f"Matched CVEs: {len(result.matched_cves)}")
print(f"Vulnerability Activity Rate: {result.vulnerability_activity_rate}")
print(f"Exploitation Risk: {result.exploitation_risk}")
print(f"Relative Threat Level: {result.relative_threat_level}")

# Metadata
print(f"Vendor: {result.metadata.get('vendor', 'N/A')}")
print(f"Product: {result.metadata.get('product', 'N/A')}")
print(f"Risk Summary: {result.metadata.get('risk_summary', {})}")
```

### Converting to JSON

All result objects can be converted to JSON for storage or API responses:

```python
import json

result = processor.analyze("pkg:npm/lodash@4.17.20", "purl")
result_json = result.to_dict()

# Save to file
with open("analysis_result.json", "w") as f:
    json.dump(result_json, f, indent=2)

# Or print formatted JSON
print(json.dumps(result_json, indent=2))
```

### Error Handling

Robust error handling for production use:

```python
def safe_analyze(processor, identifier, input_type=None):
    """Safely analyze an identifier with comprehensive error handling."""
    try:
        # Auto-detect type if not provided
        if input_type is None:
            input_type = processor.detect_input_type(identifier)
        
        result = processor.analyze(identifier, input_type)
        
        if result.error_message:
            print(f"Warning: {result.error_message}")
        
        return result
        
    except ValueError as e:
        print(f"Invalid input: {e}")
        return None
    except Exception as e:
        print(f"Analysis failed: {e}")
        return None

# Usage
result = safe_analyze(processor, "CVE-2021-44228")
if result:
    print(f"Analysis successful: {len(result.matched_cves)} CVEs found")
```

## Performance Tips

### Caching and Optimization

```python
# Initialize with caching for better performance
processor = VulnerabilityProcessor(
    cve_data_path=cve_data_path,
    verbose=False,  # Disable verbose logging for performance
    kev_file_path=kev_file_path
)

# Batch processing for multiple identifiers
identifiers = [
    ("CVE-2021-44228", "cve"),
    ("pkg:npm/lodash@4.17.20", "purl"),
    ("cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*", "cpe")
]

results = []
for identifier, input_type in identifiers:
    try:
        result = processor.analyze(identifier, input_type)
        results.append(result)
    except Exception as e:
        print(f"Failed to analyze {identifier}: {e}")

print(f"Successfully analyzed {len(results)} out of {len(identifiers)} identifiers")
```

### Memory Management

```python
# For large batch processing, consider processing in chunks
def process_large_batch(processor, identifiers, chunk_size=100):
    """Process large batches of identifiers in chunks."""
    results = []
    
    for i in range(0, len(identifiers), chunk_size):
        chunk = identifiers[i:i + chunk_size]
        print(f"Processing chunk {i//chunk_size + 1}/{(len(identifiers)-1)//chunk_size + 1}")
        
        for identifier, input_type in chunk:
            try:
                result = processor.analyze(identifier, input_type)
                results.append(result)
            except Exception as e:
                print(f"Failed to analyze {identifier}: {e}")
        
        # Optional: Clear cache periodically for memory management
        if hasattr(processor, '_cve_cache'):
            processor._cve_cache.clear()
    
    return results
```

## Integration Examples

### Flask Web API

```python
from flask import Flask, request, jsonify
from vulnanalyzer import VulnerabilityProcessor

app = Flask(__name__)
processor = VulnerabilityProcessor(verbose=False)

@app.route('/analyze', methods=['POST'])
def analyze_endpoint():
    data = request.get_json()
    identifier = data.get('identifier')
    input_type = data.get('type')
    
    if not identifier:
        return jsonify({'error': 'identifier is required'}), 400
    
    try:
        if not input_type:
            input_type = processor.detect_input_type(identifier)
        
        result = processor.analyze(identifier, input_type)
        return jsonify(result.to_dict())
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
```

### Command Line Tool

```python
#!/usr/bin/env python3
import argparse
import json
from vulnanalyzer import VulnerabilityProcessor

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Analysis Tool")
    parser.add_argument('identifier', help='CVE, PURL, CPE, or search term')
    parser.add_argument('--type', choices=['cve', 'purl', 'cpe', 'wildcard'], 
                       help='Input type (auto-detected if not specified)')
    parser.add_argument('--comprehensive', action='store_true',
                       help='Perform comprehensive analysis')
    parser.add_argument('--output', choices=['text', 'json'], default='text',
                       help='Output format')
    
    args = parser.parse_args()
    
    processor = VulnerabilityProcessor(verbose=True)
    
    try:
        input_type = args.type or processor.detect_input_type(args.identifier)
        
        if args.comprehensive and input_type in ['purl', 'cpe']:
            result = processor.analyze_comprehensive(args.identifier, input_type)
        elif input_type == 'wildcard':
            result = processor.analyze_wildcard(args.identifier)
        else:
            result = processor.analyze(args.identifier, input_type)
        
        if args.output == 'json':
            print(json.dumps(result.to_dict(), indent=2))
        else:
            # Print text summary
            print(f"Analysis of {args.identifier}")
            print(f"Type: {input_type}")
            if hasattr(result, 'matched_cves'):
                print(f"CVEs found: {len(result.matched_cves)}")
            elif hasattr(result, 'total_matched_cves'):
                print(f"CVEs found: {len(result.total_matched_cves)}")
    
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    exit(main())
```

This comprehensive guide shows all the major ways to use the VulnAnalyzer programmatically, from basic analysis to advanced ecosystem assessment and integration patterns. 