"""Data processor for vulnerability analysis."""

import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse
import logging

from tqdm import tqdm

from .models import AnalysisResult, CVERecord, MetricsData


class VulnerabilityProcessor:
    """Main processor for vulnerability analysis."""
    
    def __init__(self, cve_data_path: Path, verbose: bool = False):
        """Initialize the processor with CVE data path."""
        self.cve_data_path = cve_data_path
        self.verbose = verbose
        self.logger = self._setup_logger()
        
        # Cache for performance
        self._cve_cache: Dict[str, CVERecord] = {}
        self._loaded_years: set = set()
    
    def _setup_logger(self) -> logging.Logger:
        """Set up logger for the processor."""
        logger = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO if self.verbose else logging.WARNING)
        return logger
    
    def detect_input_type(self, identifier: str) -> str:
        """Detect the type of input identifier."""
        identifier = identifier.strip()
        
        # CVE pattern: CVE-YYYY-NNNN
        if re.match(r'^CVE-\d{4}-\d{4,}$', identifier, re.IGNORECASE):
            return "cve"
        
        # PURL pattern: pkg:type/namespace/name@version
        if identifier.startswith('pkg:'):
            return "purl"
        
        # CPE pattern: cpe:version:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
        if identifier.startswith('cpe:'):
            return "cpe"
        
        # Default fallback - try to guess based on content
        if '/' in identifier and ('@' in identifier or ':' in identifier):
            return "purl"
        
        raise ValueError(f"Unable to detect input type for: {identifier}")
    
    def analyze(self, identifier: str, input_type: str) -> AnalysisResult:
        """Analyze vulnerability data for the given identifier."""
        try:
            self.logger.info(f"Starting analysis for {identifier} (type: {input_type})")
            
            # Parse the identifier based on type
            if input_type.lower() == "cve":
                return self._analyze_cve(identifier)
            elif input_type.lower() == "purl":
                return self._analyze_purl(identifier)
            elif input_type.lower() == "cpe":
                return self._analyze_cpe(identifier)
            else:
                raise ValueError(f"Unsupported input type: {input_type}")
                
        except Exception as e:
            self.logger.error(f"Analysis failed: {str(e)}")
            return AnalysisResult(
                identifier=identifier,
                input_type=input_type,
                matched_cves=[],
                introduction_rate=0.0,
                history_usage_rate=0.0,
                analysis_period="N/A",
                total_cves_analyzed=0,
                error_message=str(e)
            )
    
    def _analyze_cve(self, cve_id: str) -> AnalysisResult:
        """Analyze a specific CVE ID."""
        cve_id = cve_id.upper()
        
        # Extract year from CVE ID
        year_match = re.search(r'CVE-(\d{4})-', cve_id)
        if not year_match:
            raise ValueError(f"Invalid CVE format: {cve_id}")
        
        year = year_match.group(1)
        
        # Load CVE data for the specific year
        cve_record = self._load_cve_by_id(cve_id, year)
        if not cve_record:
            return AnalysisResult(
                identifier=cve_id,
                input_type="cve",
                matched_cves=[],
                introduction_rate=0.0,
                history_usage_rate=0.0,
                analysis_period=f"Year {year}",
                total_cves_analyzed=0,
                error_message=f"CVE {cve_id} not found"
            )
        
        # For CVE analysis, we look at related vulnerabilities
        related_cves = self._find_related_cves(cve_record)
        
        # Calculate metrics based on the CVE and related vulnerabilities
        metrics = self._calculate_cve_metrics(cve_record, related_cves)
        
        return AnalysisResult(
            identifier=cve_id,
            input_type="cve",
            matched_cves=[cve_id] + related_cves,
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"Year {year}",
            total_cves_analyzed=metrics.total_cves,
            metadata={
                "vendor": cve_record.vendor,
                "product": cve_record.product,
                "published_date": cve_record.published_date.isoformat(),
                "problem_types": cve_record.problem_types
            }
        )
    
    def _analyze_purl(self, purl: str) -> AnalysisResult:
        """Analyze a Package URL (PURL)."""
        parsed_purl = self._parse_purl(purl)
        
        # Search for CVEs related to this package
        matched_cves = self._search_cves_by_package(
            parsed_purl['type'],
            parsed_purl['namespace'],
            parsed_purl['name'],
            parsed_purl['version']
        )
        
        # Calculate metrics
        metrics = self._calculate_package_metrics(parsed_purl, matched_cves)
        
        return AnalysisResult(
            identifier=purl,
            input_type="purl",
            matched_cves=matched_cves,
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"All years (focused on {parsed_purl['name']})",
            total_cves_analyzed=metrics.total_cves,
            metadata={
                "package_type": parsed_purl['type'],
                "package_name": parsed_purl['name'],
                "package_version": parsed_purl['version'],
                "namespace": parsed_purl['namespace']
            }
        )
    
    def _analyze_cpe(self, cpe: str) -> AnalysisResult:
        """Analyze a Common Platform Enumeration (CPE)."""
        parsed_cpe = self._parse_cpe(cpe)
        
        # Search for CVEs related to this CPE
        matched_cves = self._search_cves_by_cpe(parsed_cpe)
        
        # Calculate metrics
        metrics = self._calculate_cpe_metrics(parsed_cpe, matched_cves)
        
        return AnalysisResult(
            identifier=cpe,
            input_type="cpe",
            matched_cves=matched_cves,
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"All years (focused on {parsed_cpe.get('product', 'unknown')})",
            total_cves_analyzed=metrics.total_cves,
            metadata={
                "vendor": parsed_cpe.get('vendor', 'unknown'),
                "product": parsed_cpe.get('product', 'unknown'),
                "version": parsed_cpe.get('version', 'unknown'),
                "part": parsed_cpe.get('part', 'unknown')
            }
        )
    
    def _load_cve_by_id(self, cve_id: str, year: str) -> Optional[CVERecord]:
        """Load a specific CVE by ID and year."""
        if cve_id in self._cve_cache:
            return self._cve_cache[cve_id]
        
        # Extract the number part for directory structure
        cve_num = cve_id.split('-')[2]
        if cve_num.isdigit():
            # Group by thousands (e.g., 0xxx, 1xxx, 2xxx, 10xxx, 20xxx)
            num_value = int(cve_num)
            thousands = num_value // 1000
            dir_name = f"{thousands}xxx"
        else:
            dir_name = "0xxx"
        
        cve_file = self.cve_data_path / year / dir_name / f"{cve_id}.json"
        
        if not cve_file.exists():
            return None
        
        try:
            with open(cve_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            record = CVERecord.from_json(data)
            self._cve_cache[cve_id] = record
            return record
        except Exception as e:
            self.logger.error(f"Error loading CVE {cve_id}: {str(e)}")
            return None
    
    def _find_related_cves(self, cve_record: CVERecord) -> List[str]:
        """Find CVEs related to the given CVE record."""
        related_cves = []
        
        # Search for CVEs with same vendor/product
        search_terms = [
            cve_record.vendor.lower(),
            cve_record.product.lower()
        ]
        
        # Load a sample of CVEs from recent years for comparison
        for year in ['2023', '2022', '2021', '2020']:
            year_cves = self._load_cves_for_year(year, limit=1000)
            for cve in year_cves:
                if (cve.vendor.lower() in search_terms or 
                    cve.product.lower() in search_terms or
                    any(term in cve.description.lower() for term in search_terms)):
                    related_cves.append(cve.cve_id)
        
        return related_cves[:50]  # Limit to prevent overwhelming results
    
    def _load_cves_for_year(self, year: str, limit: Optional[int] = None) -> List[CVERecord]:
        """Load CVEs for a specific year."""
        if year in self._loaded_years:
            return [cve for cve in self._cve_cache.values() 
                   if cve.cve_id.startswith(f"CVE-{year}-")]
        
        year_path = self.cve_data_path / year
        if not year_path.exists():
            return []
        
        cves = []
        count = 0
        
        # Iterate through all subdirectories
        for subdir in year_path.iterdir():
            if not subdir.is_dir():
                continue
                
            for cve_file in subdir.glob("*.json"):
                if limit and count >= limit:
                    break
                    
                try:
                    with open(cve_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    
                    record = CVERecord.from_json(data)
                    cves.append(record)
                    self._cve_cache[record.cve_id] = record
                    count += 1
                except Exception as e:
                    self.logger.warning(f"Error loading {cve_file}: {str(e)}")
                    continue
        
        self._loaded_years.add(year)
        return cves
    
    def _parse_purl(self, purl: str) -> Dict[str, str]:
        """Parse a Package URL (PURL) into components."""
        # Basic PURL parsing: pkg:type/namespace/name@version?qualifiers#subpath
        if not purl.startswith('pkg:'):
            raise ValueError(f"Invalid PURL format: {purl}")
        
        purl = purl[4:]  # Remove 'pkg:' prefix
        
        # Split by '/' and '@' to get components
        parts = purl.split('/')
        if len(parts) < 2:
            raise ValueError(f"Invalid PURL format: {purl}")
        
        package_type = parts[0]
        
        # Handle namespace and name
        if len(parts) == 2:
            namespace = None
            name_version = parts[1]
        else:
            namespace = parts[1]
            name_version = '/'.join(parts[2:])
        
        # Extract name and version
        if '@' in name_version:
            name, version = name_version.split('@', 1)
        else:
            name = name_version
            version = None
        
        return {
            'type': package_type,
            'namespace': namespace,
            'name': name,
            'version': version
        }
    
    def _parse_cpe(self, cpe: str) -> Dict[str, str]:
        """Parse a CPE string into components."""
        if not cpe.startswith('cpe:'):
            raise ValueError(f"Invalid CPE format: {cpe}")
        
        parts = cpe.split(':')
        if len(parts) < 5:
            raise ValueError(f"Invalid CPE format: {cpe}")
        
        return {
            'cpe_version': parts[1],
            'part': parts[2],
            'vendor': parts[3],
            'product': parts[4],
            'version': parts[5] if len(parts) > 5 else '*',
            'update': parts[6] if len(parts) > 6 else '*',
            'edition': parts[7] if len(parts) > 7 else '*',
            'language': parts[8] if len(parts) > 8 else '*'
        }
    
    def _search_cves_by_package(self, pkg_type: str, namespace: Optional[str], 
                               name: str, version: Optional[str]) -> List[str]:
        """Search for CVEs related to a package."""
        matched_cves = []
        search_terms = [name.lower()]
        
        if namespace:
            search_terms.append(namespace.lower())
        
        # Search through recent years
        for year in ['2024', '2023', '2022', '2021', '2020']:
            year_cves = self._load_cves_for_year(year, limit=2000)
            for cve in year_cves:
                if any(term in cve.product.lower() or term in cve.description.lower() 
                       for term in search_terms):
                    matched_cves.append(cve.cve_id)
        
        return matched_cves[:100]  # Limit results
    
    def _search_cves_by_cpe(self, cpe_data: Dict[str, str]) -> List[str]:
        """Search for CVEs related to a CPE."""
        matched_cves = []
        vendor = cpe_data.get('vendor', '').lower()
        product = cpe_data.get('product', '').lower()
        
        # Search through recent years
        for year in ['2024', '2023', '2022', '2021', '2020']:
            year_cves = self._load_cves_for_year(year, limit=2000)
            for cve in year_cves:
                if (vendor in cve.vendor.lower() or 
                    product in cve.product.lower() or
                    vendor in cve.description.lower() or
                    product in cve.description.lower()):
                    matched_cves.append(cve.cve_id)
        
        return matched_cves[:100]  # Limit results
    
    def _calculate_cve_metrics(self, cve_record: CVERecord, related_cves: List[str]) -> MetricsData:
        """Calculate metrics for CVE analysis."""
        # For CVE analysis, we consider the introduction rate as the relationship
        # between this CVE and similar vulnerabilities
        total_cves = len(related_cves) + 1  # Include the original CVE
        matched_cves = total_cves  # All are "matched" in this context
        
        # Calculate time-based metrics
        days_since_publication = (datetime.now() - cve_record.published_date).days
        
        # Usage rate based on references and problem types
        usage_events = len(cve_record.references) + len(cve_record.problem_types)
        
        return MetricsData(
            total_cves=total_cves,
            matched_cves=matched_cves,
            time_period_days=days_since_publication,
            introduction_events=len(related_cves),
            usage_events=usage_events
        )
    
    def _calculate_package_metrics(self, purl_data: Dict[str, str], matched_cves: List[str]) -> MetricsData:
        """Calculate metrics for package analysis."""
        # Estimate total CVEs in the system (sample from recent years)
        total_sample = 0
        for year in ['2024', '2023', '2022', '2021', '2020']:
            year_cves = self._load_cves_for_year(year, limit=5000)
            total_sample += len(year_cves)
        
        return MetricsData(
            total_cves=total_sample,
            matched_cves=len(matched_cves),
            time_period_days=365 * 5,  # 5 years
            introduction_events=len(matched_cves),
            usage_events=len(matched_cves) // 2  # Rough estimate
        )
    
    def _calculate_cpe_metrics(self, cpe_data: Dict[str, str], matched_cves: List[str]) -> MetricsData:
        """Calculate metrics for CPE analysis."""
        # Similar to package metrics but focused on vendor/product
        total_sample = 0
        for year in ['2024', '2023', '2022', '2021', '2020']:
            year_cves = self._load_cves_for_year(year, limit=5000)
            total_sample += len(year_cves)
        
        return MetricsData(
            total_cves=total_sample,
            matched_cves=len(matched_cves),
            time_period_days=365 * 5,  # 5 years
            introduction_events=len(matched_cves),
            usage_events=len(matched_cves) // 3  # Conservative estimate
        ) 