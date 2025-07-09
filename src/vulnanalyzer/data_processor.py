"""Data processor for vulnerability analysis."""

import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from urllib.parse import urlparse
import logging

from tqdm import tqdm

from .models import AnalysisResult, CVERecord, MetricsData, ComponentAnalysisResult, ComprehensiveAnalysisResult, WildcardAnalysisResult, CategoryAnalysisResult


class VulnerabilityProcessor:
    """Main processor for vulnerability analysis."""
    
    def __init__(self, cve_data_path: Optional[Path] = None, verbose: bool = False, kev_file_path: Optional[Path] = None):
        """Initialize the processor with CVE data path."""
        # Use environment variables for default paths
        if cve_data_path is None:
            cve_data_path = Path(os.getenv('CVE_DATA_PATH', os.path.expanduser('~/.vulnanalyzer/cvelistV5/cves')))
        
        self.cve_data_path = cve_data_path
        self.verbose = verbose
        self.logger = self._setup_logger()
        
        # Setup KEV file path
        if kev_file_path is None:
            env_kev_path = os.getenv('KEV_FILE_PATH')
            if env_kev_path:
                self.kev_file_path = Path(env_kev_path)
            else:
                self.kev_file_path = Path(os.path.expanduser('~/.vulnanalyzer/known_exploited_vulnerabilities.json'))
        else:
            self.kev_file_path = kev_file_path
        
        # Cache for performance
        self._cve_cache: Dict[str, CVERecord] = {}
        self._loaded_years: set = set()
        self._kev_cves: Set[str] = set()
        self._total_cves_in_db = 0
        self._total_kev_entries = 0
        
        # Load KEV data on initialization
        self._load_kev_data()
    
    def _setup_logger(self) -> logging.Logger:
        """Set up logger for the processor."""
        logger = logging.getLogger(__name__)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO if self.verbose else logging.WARNING)
        return logger
    
    def _load_kev_data(self) -> None:
        """Load known exploited vulnerabilities data."""
        if not self.kev_file_path.exists():
            self.logger.warning(f"KEV file not found: {self.kev_file_path}")
            return
        
        try:
            with open(self.kev_file_path, 'r', encoding='utf-8') as f:
                kev_data = json.load(f)
            
            vulnerabilities = kev_data.get("vulnerabilities", [])
            self._kev_cves = {vuln.get("cveID", "").upper() for vuln in vulnerabilities if vuln.get("cveID")}
            self._total_kev_entries = len(vulnerabilities)
            
            self.logger.info(f"Loaded {len(self._kev_cves)} known exploited vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error loading KEV data: {str(e)}")
    
    def _get_total_cves_count(self) -> int:
        """Get total count of CVEs in the database."""
        if self._total_cves_in_db > 0:
            return self._total_cves_in_db
        
        count = 0
        for year_dir in self.cve_data_path.iterdir():
            if year_dir.is_dir() and year_dir.name.isdigit():
                for subdir in year_dir.iterdir():
                    if subdir.is_dir():
                        count += len(list(subdir.glob("*.json")))
        
        self._total_cves_in_db = count
        return count
    
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
        
        # Wildcard pattern: term * or just term (for comprehensive search)
        if identifier.endswith(' *') or (len(identifier.split()) == 1 and not '/' in identifier and not ':' in identifier):
            return "wildcard"
        
        # Default fallback - try to guess based on content
        if '/' in identifier and ('@' in identifier or ':' in identifier):
            return "purl"
        
        # If we can't detect anything else, treat as wildcard search
        return "wildcard"
    
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
            elif input_type.lower() == "wildcard":
                # For wildcard, convert to basic analysis result for compatibility
                wildcard_result = self.analyze_wildcard(identifier)
                return self._convert_wildcard_to_analysis(wildcard_result)
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
    
    def analyze_comprehensive(self, identifier: str, input_type: str) -> ComprehensiveAnalysisResult:
        """Perform comprehensive component analysis for PURL or CPE identifiers."""
        try:
            self.logger.info(f"Starting comprehensive analysis for {identifier} (type: {input_type})")
            
            if input_type.lower() == "purl":
                return self._analyze_purl_comprehensive(identifier)
            elif input_type.lower() == "cpe":
                return self._analyze_cpe_comprehensive(identifier)
            else:
                # For CVE, just return regular analysis wrapped in comprehensive result
                regular_analysis = self.analyze(identifier, input_type)
                return ComprehensiveAnalysisResult(
                    identifier=identifier,
                    input_type=input_type,
                    overall_analysis=regular_analysis,
                    component_analyses=[],
                    aggregated_metrics={},
                    recommendations=["CVE analysis does not support component breakdown"]
                )
                
        except Exception as e:
            self.logger.error(f"Comprehensive analysis failed: {str(e)}")
            # Return error wrapped in comprehensive result
            error_analysis = AnalysisResult(
                identifier=identifier,
                input_type=input_type,
                matched_cves=[],
                introduction_rate=0.0,
                history_usage_rate=0.0,
                analysis_period="N/A",
                total_cves_analyzed=0,
                error_message=str(e)
            )
            return ComprehensiveAnalysisResult(
                identifier=identifier,
                input_type=input_type,
                overall_analysis=error_analysis,
                component_analyses=[],
                aggregated_metrics={},
                recommendations=[]
            )
    
    def analyze_wildcard(self, search_term: str) -> WildcardAnalysisResult:
        """Perform comprehensive wildcard analysis for a search term."""
        try:
            # Clean up the search term
            search_term = search_term.strip()
            if search_term.endswith(' *'):
                search_term = search_term[:-2].strip()
            
            self.logger.info(f"Starting wildcard analysis for '{search_term}'")
            
            # Search across all categories
            category_analyses = []
            all_matched_cves = set()
            
            # Search in vendors
            vendor_analysis = self._analyze_category_search(search_term, "vendors", "vendor")
            if vendor_analysis:
                category_analyses.append(vendor_analysis)
                all_matched_cves.update(sum(vendor_analysis.matches.values(), []))
            
            # Search in products
            product_analysis = self._analyze_category_search(search_term, "products", "product")
            if product_analysis:
                category_analyses.append(product_analysis)
                all_matched_cves.update(sum(product_analysis.matches.values(), []))
            
            # Search in descriptions
            description_analysis = self._analyze_category_search(search_term, "descriptions", "description")
            if description_analysis:
                category_analyses.append(description_analysis)
                all_matched_cves.update(sum(description_analysis.matches.values(), []))
            
            # Search in problem types
            problem_type_analysis = self._analyze_category_search(search_term, "problem_types", "problem_type")
            if problem_type_analysis:
                category_analyses.append(problem_type_analysis)
                all_matched_cves.update(sum(problem_type_analysis.matches.values(), []))
            
            all_matched_cves = list(all_matched_cves)
            
            # Calculate overall metrics
            overall_metrics = self._calculate_wildcard_overall_metrics(all_matched_cves)
            
            # Temporal analysis
            temporal_analysis = self._calculate_temporal_analysis(all_matched_cves)
            
            # Generate recommendations
            recommendations = self._generate_wildcard_recommendations(search_term, category_analyses, overall_metrics)
            
            return WildcardAnalysisResult(
                search_term=search_term,
                input_type="wildcard",
                total_matched_cves=all_matched_cves,
                category_analyses=category_analyses,
                overall_metrics=overall_metrics,
                temporal_analysis=temporal_analysis,
                recommendations=recommendations
            )
            
        except Exception as e:
            self.logger.error(f"Wildcard analysis failed: {str(e)}")
            return WildcardAnalysisResult(
                search_term=search_term,
                input_type="wildcard",
                total_matched_cves=[],
                category_analyses=[],
                overall_metrics={},
                temporal_analysis={},
                recommendations=[],
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
        
        # Create enhanced analysis result
        result = AnalysisResult(
            identifier=cve_id,
            input_type="cve",
            matched_cves=[cve_id] + related_cves,
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"Year {year}",
            total_cves_analyzed=metrics.total_cves,
            vulnerability_activity_rate=metrics.calculate_vulnerability_activity_rate(),
            exploitation_risk=metrics.calculate_exploitation_risk(),
            relative_threat_level=metrics.calculate_relative_threat_level(),
            metadata={
                "vendor": cve_record.vendor,
                "product": cve_record.product,
                "published_date": cve_record.published_date.isoformat(),
                "problem_types": cve_record.problem_types,
                "risk_summary": metrics.get_risk_summary()
            }
        )
        
        return result
    
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
        
        # Create enhanced analysis result
        result = AnalysisResult(
            identifier=purl,
            input_type="purl",
            matched_cves=matched_cves,
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"All years (focused on {parsed_purl['name']})",
            total_cves_analyzed=metrics.total_cves,
            vulnerability_activity_rate=metrics.calculate_vulnerability_activity_rate(),
            exploitation_risk=metrics.calculate_exploitation_risk(),
            relative_threat_level=metrics.calculate_relative_threat_level(),
            metadata={
                "package_type": parsed_purl['type'],
                "package_name": parsed_purl['name'],
                "package_version": parsed_purl['version'],
                "namespace": parsed_purl['namespace'],
                "risk_summary": metrics.get_risk_summary()
            }
        )
        
        return result
    
    def _analyze_cpe(self, cpe: str) -> AnalysisResult:
        """Analyze a Common Platform Enumeration (CPE)."""
        parsed_cpe = self._parse_cpe(cpe)
        
        # Search for CVEs related to this CPE
        matched_cves = self._search_cves_by_cpe(parsed_cpe)
        
        # Calculate metrics
        metrics = self._calculate_cpe_metrics(parsed_cpe, matched_cves)
        
        # Create enhanced analysis result
        result = AnalysisResult(
            identifier=cpe,
            input_type="cpe",
            matched_cves=matched_cves,
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"All years (focused on {parsed_cpe.get('product', 'unknown')})",
            total_cves_analyzed=metrics.total_cves,
            vulnerability_activity_rate=metrics.calculate_vulnerability_activity_rate(),
            exploitation_risk=metrics.calculate_exploitation_risk(),
            relative_threat_level=metrics.calculate_relative_threat_level(),
            metadata={
                "vendor": parsed_cpe.get('vendor', 'unknown'),
                "product": parsed_cpe.get('product', 'unknown'),
                "version": parsed_cpe.get('version', 'unknown'),
                "part": parsed_cpe.get('part', 'unknown'),
                "risk_summary": metrics.get_risk_summary()
            }
        )
        
        return result
    
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
        
        # Load a sample of CVEs from recent and historical years for comparison
        years_to_search = ['2024', '2023', '2022', '2021', '2020', '2019', '2018', '2017', '2016', '2015']
        for year in years_to_search:
            year_cves = self._load_cves_for_year(year, limit=500)  # Reduced limit for performance
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
        
        # Search through recent and some historical years for better context
        for year in ['2024', '2023', '2022', '2021', '2020', '2019', '2018', '2017']:
            year_cves = self._load_cves_for_year(year, limit=1000)
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
        
        # Search through recent and some historical years for better context
        for year in ['2024', '2023', '2022', '2021', '2020', '2019', '2018', '2017']:
            year_cves = self._load_cves_for_year(year, limit=1000)
            for cve in year_cves:
                if (vendor in cve.vendor.lower() or 
                    product in cve.product.lower() or
                    vendor in cve.description.lower() or
                    product in cve.description.lower()):
                    matched_cves.append(cve.cve_id)
        
        return matched_cves[:100]  # Limit results
    
    def _calculate_cve_metrics(self, cve_record: CVERecord, related_cves: List[str]) -> MetricsData:
        """Calculate enhanced metrics for CVE analysis."""
        recent_cves = []
        historical_cves = []
        all_matched_cves = [cve_record.cve_id] + related_cves
        
        for cve_id in all_matched_cves:
            # Extract year from CVE ID
            year_match = re.search(r'CVE-(\d{4})-', cve_id)
            if year_match:
                year = int(year_match.group(1))
                if 2020 <= year <= 2025:
                    recent_cves.append(cve_id)
                elif year < 2020:
                    historical_cves.append(cve_id)
        
        # Check if any matched CVEs are in KEV
        kev_matches = sum(1 for cve_id in all_matched_cves if cve_id.upper() in self._kev_cves)
        
        # Get total CVEs in database
        total_cves_in_db = self._get_total_cves_count()
        
        return MetricsData(
            total_cves=total_cves_in_db,
            matched_cves=len(all_matched_cves),
            recent_matched_cves=len(recent_cves),
            historical_matched_cves=len(historical_cves),
            kev_matches=kev_matches,
            total_kev_entries=self._total_kev_entries
        )
    
    def _calculate_package_metrics(self, purl_data: Dict[str, str], matched_cves: List[str]) -> MetricsData:
        """Calculate enhanced metrics for package analysis."""
        recent_cves = []
        historical_cves = []
        
        for cve_id in matched_cves:
            year_match = re.search(r'CVE-(\d{4})-', cve_id)
            if year_match:
                year = int(year_match.group(1))
                if 2020 <= year <= 2025:
                    recent_cves.append(cve_id)
                elif year < 2020:
                    historical_cves.append(cve_id)
        
        # Check if any matched CVEs are in KEV
        kev_matches = sum(1 for cve_id in matched_cves if cve_id.upper() in self._kev_cves)
        
        # Get total CVEs in database
        total_cves_in_db = self._get_total_cves_count()
        
        return MetricsData(
            total_cves=total_cves_in_db,
            matched_cves=len(matched_cves),
            recent_matched_cves=len(recent_cves),
            historical_matched_cves=len(historical_cves),
            kev_matches=kev_matches,
            total_kev_entries=self._total_kev_entries
        )
    
    def _calculate_cpe_metrics(self, cpe_data: Dict[str, str], matched_cves: List[str]) -> MetricsData:
        """Calculate enhanced metrics for CPE analysis."""
        recent_cves = []
        historical_cves = []
        
        for cve_id in matched_cves:
            year_match = re.search(r'CVE-(\d{4})-', cve_id)
            if year_match:
                year = int(year_match.group(1))
                if 2020 <= year <= 2025:
                    recent_cves.append(cve_id)
                elif year < 2020:
                    historical_cves.append(cve_id)
        
        # Check if any matched CVEs are in KEV
        kev_matches = sum(1 for cve_id in matched_cves if cve_id.upper() in self._kev_cves)
        
        # Get total CVEs in database
        total_cves_in_db = self._get_total_cves_count()
        
        return MetricsData(
            total_cves=total_cves_in_db,
            matched_cves=len(matched_cves),
            recent_matched_cves=len(recent_cves),
            historical_matched_cves=len(historical_cves),
            kev_matches=kev_matches,
            total_kev_entries=self._total_kev_entries
        ) 

    def _analyze_purl_comprehensive(self, purl: str) -> ComprehensiveAnalysisResult:
        """Perform comprehensive analysis of PURL components."""
        parsed_purl = self._parse_purl(purl)
        
        # Get overall analysis first
        overall_analysis = self._analyze_purl(purl)
        
        component_analyses = []
        
        # Analyze package type
        if parsed_purl['type']:
            type_analysis = self._analyze_component(
                component_name="Package Type",
                component_type="package_type",
                component_value=parsed_purl['type'],
                search_terms=[parsed_purl['type']]
            )
            component_analyses.append(type_analysis)
        
        # Analyze namespace
        if parsed_purl['namespace']:
            namespace_analysis = self._analyze_component(
                component_name="Namespace", 
                component_type="namespace",
                component_value=parsed_purl['namespace'],
                search_terms=[parsed_purl['namespace']]
            )
            component_analyses.append(namespace_analysis)
        
        # Analyze package name (most important)
        if parsed_purl['name']:
            name_analysis = self._analyze_component(
                component_name="Package Name",
                component_type="package_name", 
                component_value=parsed_purl['name'],
                search_terms=[parsed_purl['name']]
            )
            component_analyses.append(name_analysis)
        
        # Analyze version (if specified)
        if parsed_purl['version']:
            version_analysis = self._analyze_component(
                component_name="Version",
                component_type="version",
                component_value=parsed_purl['version'],
                search_terms=[parsed_purl['name'], parsed_purl['version']]  # Search for name+version
            )
            component_analyses.append(version_analysis)
        
        # Create aggregated metrics
        aggregated_metrics = self._aggregate_component_metrics(component_analyses)
        
        # Generate recommendations
        recommendations = self._generate_purl_recommendations(parsed_purl, component_analyses, overall_analysis)
        
        return ComprehensiveAnalysisResult(
            identifier=purl,
            input_type="purl",
            overall_analysis=overall_analysis,
            component_analyses=component_analyses,
            aggregated_metrics=aggregated_metrics,
            recommendations=recommendations
        )
    
    def _analyze_cpe_comprehensive(self, cpe: str) -> ComprehensiveAnalysisResult:
        """Perform comprehensive analysis of CPE components."""
        parsed_cpe = self._parse_cpe(cpe)
        
        # Get overall analysis first
        overall_analysis = self._analyze_cpe(cpe)
        
        component_analyses = []
        
        # Analyze vendor
        if parsed_cpe.get('vendor') and parsed_cpe['vendor'] != '*':
            vendor_analysis = self._analyze_component(
                component_name="Vendor",
                component_type="vendor",
                component_value=parsed_cpe['vendor'],
                search_terms=[parsed_cpe['vendor']]
            )
            component_analyses.append(vendor_analysis)
        
        # Analyze product
        if parsed_cpe.get('product') and parsed_cpe['product'] != '*':
            product_analysis = self._analyze_component(
                component_name="Product",
                component_type="product",
                component_value=parsed_cpe['product'],
                search_terms=[parsed_cpe['product']]
            )
            component_analyses.append(product_analysis)
        
        # Analyze vendor+product combination (often most relevant)
        if (parsed_cpe.get('vendor') and parsed_cpe['vendor'] != '*' and 
            parsed_cpe.get('product') and parsed_cpe['product'] != '*'):
            vendor_product_analysis = self._analyze_component(
                component_name="Vendor + Product",
                component_type="vendor_product",
                component_value=f"{parsed_cpe['vendor']} {parsed_cpe['product']}",
                search_terms=[parsed_cpe['vendor'], parsed_cpe['product']]
            )
            component_analyses.append(vendor_product_analysis)
        
        # Analyze version (if specified)
        if parsed_cpe.get('version') and parsed_cpe['version'] != '*':
            version_analysis = self._analyze_component(
                component_name="Version",
                component_type="version",
                component_value=parsed_cpe['version'],
                search_terms=[parsed_cpe['product'], parsed_cpe['version']]  # Search for product+version
            )
            component_analyses.append(version_analysis)
        
        # Create aggregated metrics
        aggregated_metrics = self._aggregate_component_metrics(component_analyses)
        
        # Generate recommendations
        recommendations = self._generate_cpe_recommendations(parsed_cpe, component_analyses, overall_analysis)
        
        return ComprehensiveAnalysisResult(
            identifier=cpe,
            input_type="cpe",
            overall_analysis=overall_analysis,
            component_analyses=component_analyses,
            aggregated_metrics=aggregated_metrics,
            recommendations=recommendations
        )
    
    def _analyze_component(self, component_name: str, component_type: str, 
                          component_value: str, search_terms: List[str]) -> ComponentAnalysisResult:
        """Analyze a single component for vulnerabilities."""
        matched_cves = []
        
        # Search through recent and historical years
        for year in ['2024', '2023', '2022', '2021', '2020', '2019', '2018', '2017', '2016', '2015']:
            year_cves = self._load_cves_for_year(year, limit=1000)
            for cve in year_cves:
                # Check if any search terms match in vendor, product, or description
                if any(term.lower() in cve.vendor.lower() or 
                       term.lower() in cve.product.lower() or
                       term.lower() in cve.description.lower() 
                       for term in search_terms if term):
                    matched_cves.append(cve.cve_id)
        
        # Remove duplicates
        matched_cves = list(set(matched_cves))
        
        # Calculate metrics for this component
        metrics = self._calculate_component_metrics(matched_cves)
        
        return ComponentAnalysisResult(
            component_name=component_name,
            component_type=component_type,
            component_value=component_value,
            matched_cves=matched_cves[:100],  # Limit for performance
            vulnerability_activity_rate=metrics.calculate_vulnerability_activity_rate(),
            exploitation_risk=metrics.calculate_exploitation_risk(),
            relative_threat_level=metrics.calculate_relative_threat_level(),
            risk_summary=metrics.get_risk_summary()
        )
    
    def _calculate_component_metrics(self, matched_cves: List[str]) -> MetricsData:
        """Calculate metrics for a component analysis."""
        recent_cves = []
        historical_cves = []
        
        for cve_id in matched_cves:
            year_match = re.search(r'CVE-(\d{4})-', cve_id)
            if year_match:
                year = int(year_match.group(1))
                if 2020 <= year <= 2025:
                    recent_cves.append(cve_id)
                elif year < 2020:
                    historical_cves.append(cve_id)
        
        # Check if any matched CVEs are in KEV
        kev_matches = sum(1 for cve_id in matched_cves if cve_id.upper() in self._kev_cves)
        
        # Get total CVEs in database
        total_cves_in_db = self._get_total_cves_count()
        
        return MetricsData(
            total_cves=total_cves_in_db,
            matched_cves=len(matched_cves),
            recent_matched_cves=len(recent_cves),
            historical_matched_cves=len(historical_cves),
            kev_matches=kev_matches,
            total_kev_entries=self._total_kev_entries
        )
    
    def _aggregate_component_metrics(self, component_analyses: List[ComponentAnalysisResult]) -> Dict[str, Any]:
        """Aggregate metrics across all components."""
        if not component_analyses:
            return {}
        
        total_cves = sum(len(comp.matched_cves) for comp in component_analyses)
        total_exploited = sum(comp.exploitation_risk * len(comp.matched_cves) for comp in component_analyses)
        avg_exploitation_risk = total_exploited / total_cves if total_cves > 0 else 0.0
        
        avg_activity_rate = sum(comp.vulnerability_activity_rate for comp in component_analyses) / len(component_analyses)
        avg_threat_level = sum(comp.relative_threat_level for comp in component_analyses) / len(component_analyses)
        
        highest_risk_component = max(component_analyses, key=lambda x: x.exploitation_risk)
        most_active_component = max(component_analyses, key=lambda x: x.vulnerability_activity_rate)
        
        return {
            "total_unique_cves": total_cves,
            "average_exploitation_risk": avg_exploitation_risk,
            "average_activity_rate": avg_activity_rate, 
            "average_threat_level": avg_threat_level,
            "highest_risk_component_name": highest_risk_component.component_name,
            "highest_risk_value": highest_risk_component.exploitation_risk,
            "most_active_component_name": most_active_component.component_name,
            "most_active_value": most_active_component.vulnerability_activity_rate,
            "components_analyzed": len(component_analyses)
        }
    
    def _generate_purl_recommendations(self, parsed_purl: Dict[str, str], 
                                     component_analyses: List[ComponentAnalysisResult],
                                     overall_analysis: AnalysisResult) -> List[str]:
        """Generate security recommendations for PURL analysis."""
        recommendations = []
        
        if not component_analyses:
            return ["No component analysis available"]
        
        # Find highest risk components
        high_risk_components = [comp for comp in component_analyses if comp.exploitation_risk >= 0.10]
        
        if high_risk_components:
            recommendations.append(f"HIGH PRIORITY: {len(high_risk_components)} component(s) have high exploitation risk (>10%)")
            for comp in high_risk_components[:3]:  # Top 3
                recommendations.append(f"  - {comp.component_name} ({comp.component_value}): {comp.exploitation_risk:.1%} exploitation risk")
        
        # Check for version-specific issues
        version_analysis = next((comp for comp in component_analyses if comp.component_type == "version"), None)
        if version_analysis and version_analysis.exploitation_risk > 0.05:
            recommendations.append(f"Consider upgrading from version {parsed_purl.get('version', 'unknown')} - current version has {version_analysis.exploitation_risk:.1%} exploitation risk")
        
        # Check package name risk
        name_analysis = next((comp for comp in component_analyses if comp.component_type == "package_name"), None)
        if name_analysis and name_analysis.vulnerability_activity_rate >= 2.0:
            recommendations.append(f"Package '{parsed_purl.get('name', 'unknown')}' shows high recent vulnerability activity - monitor for updates")
        
        # Overall risk assessment
        if overall_analysis.exploitation_risk and overall_analysis.exploitation_risk >= 0.15:
            recommendations.append("CRITICAL: This package has very high overall exploitation risk - immediate review recommended")
        elif overall_analysis.exploitation_risk and overall_analysis.exploitation_risk >= 0.05:
            recommendations.append("MEDIUM: This package has notable exploitation risk - plan security review")
        
        return recommendations if recommendations else ["No specific security concerns identified"]
    
    def _generate_cpe_recommendations(self, parsed_cpe: Dict[str, str],
                                    component_analyses: List[ComponentAnalysisResult], 
                                    overall_analysis: AnalysisResult) -> List[str]:
        """Generate security recommendations for CPE analysis."""
        recommendations = []
        
        if not component_analyses:
            return ["No component analysis available"]
        
        # Find highest risk components
        high_risk_components = [comp for comp in component_analyses if comp.exploitation_risk >= 0.10]
        
        if high_risk_components:
            recommendations.append(f"HIGH PRIORITY: {len(high_risk_components)} component(s) have high exploitation risk (>10%)")
            for comp in high_risk_components[:3]:  # Top 3
                recommendations.append(f"  - {comp.component_name} ({comp.component_value}): {comp.exploitation_risk:.1%} exploitation risk")
        
        # Check vendor-specific risks
        vendor_analysis = next((comp for comp in component_analyses if comp.component_type == "vendor"), None)
        if vendor_analysis and vendor_analysis.exploitation_risk > 0.08:
            recommendations.append(f"Vendor '{parsed_cpe.get('vendor', 'unknown')}' products show elevated exploitation risk ({vendor_analysis.exploitation_risk:.1%})")
        
        # Check product-specific risks  
        product_analysis = next((comp for comp in component_analyses if comp.component_type == "product"), None)
        if product_analysis and product_analysis.vulnerability_activity_rate >= 2.0:
            recommendations.append(f"Product '{parsed_cpe.get('product', 'unknown')}' shows high recent vulnerability activity - monitor for patches")
        
        # Check vendor+product combination
        combo_analysis = next((comp for comp in component_analyses if comp.component_type == "vendor_product"), None)
        if combo_analysis and combo_analysis.exploitation_risk > 0.12:
            recommendations.append(f"CRITICAL: {parsed_cpe.get('vendor', 'unknown')} {parsed_cpe.get('product', 'unknown')} combination shows very high exploitation risk")
        
        # Version-specific recommendations
        version_analysis = next((comp for comp in component_analyses if comp.component_type == "version"), None)
        if version_analysis and version_analysis.exploitation_risk > 0.05:
            recommendations.append(f"Version {parsed_cpe.get('version', 'unknown')} has notable exploitation risk - check for updates")
        
        # Overall risk assessment
        if overall_analysis.exploitation_risk and overall_analysis.exploitation_risk >= 0.20:
            recommendations.append("CRITICAL: This platform/software has very high overall exploitation risk - immediate patching required")
        elif overall_analysis.exploitation_risk and overall_analysis.exploitation_risk >= 0.10:
            recommendations.append("HIGH: This platform/software has high exploitation risk - prioritize security updates")
        elif overall_analysis.exploitation_risk and overall_analysis.exploitation_risk >= 0.05:
            recommendations.append("MEDIUM: This platform/software has moderate exploitation risk - plan security review")
        
        return recommendations if recommendations else ["No specific security concerns identified"] 

    def _analyze_category_search(self, search_term: str, category_name: str, category_type: str) -> Optional[CategoryAnalysisResult]:
        """Search for a term within a specific category (vendors, products, descriptions, problem_types)."""
        matches = {}  # match_value -> list of CVE IDs
        total_cves = 0
        
        # Search through recent and historical years for comprehensive coverage
        search_years = ['2024', '2023', '2022', '2021', '2020', '2019', '2018', '2017', '2016', '2015', '2014', '2013']
        
        for year in search_years:
            year_cves = self._load_cves_for_year(year, limit=2000)  # Increased limit for comprehensive search
            for cve in year_cves:
                found_match = False
                match_value = None
                
                if category_type == "vendor":
                    if search_term.lower() in cve.vendor.lower():
                        match_value = cve.vendor
                        found_match = True
                elif category_type == "product":
                    if search_term.lower() in cve.product.lower():
                        match_value = cve.product
                        found_match = True
                elif category_type == "description":
                    if search_term.lower() in cve.description.lower():
                        # Use a snippet of the description as match value
                        desc_words = cve.description.lower().split()
                        term_index = next((i for i, word in enumerate(desc_words) if search_term.lower() in word), None)
                        if term_index is not None:
                            start = max(0, term_index - 3)
                            end = min(len(desc_words), term_index + 4)
                            match_value = ' '.join(desc_words[start:end])
                            found_match = True
                elif category_type == "problem_type":
                    for pt in cve.problem_types:
                        if search_term.lower() in pt.lower():
                            match_value = pt
                            found_match = True
                            break
                
                if found_match and match_value:
                    if match_value not in matches:
                        matches[match_value] = []
                    matches[match_value].append(cve.cve_id)
                    total_cves += 1
        
        if not matches:
            return None
        
        # Calculate metrics for this category
        all_category_cves = sum(matches.values(), [])
        unique_cves = list(set(all_category_cves))
        metrics = self._calculate_component_metrics(unique_cves)
        
        # Get top matches by CVE count
        top_matches = sorted(
            [(match, len(cve_list)) for match, cve_list in matches.items()],
            key=lambda x: x[1],
            reverse=True
        )
        
        return CategoryAnalysisResult(
            category_name=category_name,
            category_type=category_type,
            matches=matches,
            total_cves=len(unique_cves),
            unique_matches=len(matches),
            vulnerability_activity_rate=metrics.calculate_vulnerability_activity_rate(),
            exploitation_risk=metrics.calculate_exploitation_risk(),
            relative_threat_level=metrics.calculate_relative_threat_level(),
            top_matches=top_matches
        )
    
    def _calculate_wildcard_overall_metrics(self, all_matched_cves: List[str]) -> Dict[str, Any]:
        """Calculate overall metrics for wildcard analysis."""
        if not all_matched_cves:
            return {}
        
        # Count recent vs historical
        recent_cves = []
        historical_cves = []
        
        for cve_id in all_matched_cves:
            year_match = re.search(r'CVE-(\d{4})-', cve_id)
            if year_match:
                year = int(year_match.group(1))
                if 2020 <= year <= 2025:
                    recent_cves.append(cve_id)
                elif year < 2020:
                    historical_cves.append(cve_id)
        
        # Check KEV matches
        kev_matches = sum(1 for cve_id in all_matched_cves if cve_id.upper() in self._kev_cves)
        
        # Calculate metrics
        metrics = MetricsData(
            total_cves=self._get_total_cves_count(),
            matched_cves=len(all_matched_cves),
            recent_matched_cves=len(recent_cves),
            historical_matched_cves=len(historical_cves),
            kev_matches=kev_matches,
            total_kev_entries=self._total_kev_entries
        )
        
        return {
            "total_matched_cves": len(all_matched_cves),
            "recent_cves": len(recent_cves),
            "historical_cves": len(historical_cves),
            "known_exploited_cves": kev_matches,
            "vulnerability_activity_rate": metrics.calculate_vulnerability_activity_rate(),
            "exploitation_risk": metrics.calculate_exploitation_risk(),
            "relative_threat_level": metrics.calculate_relative_threat_level(),
            "database_coverage": len(all_matched_cves) / self._get_total_cves_count() if self._get_total_cves_count() > 0 else 0.0
        }
    
    def _calculate_temporal_analysis(self, all_matched_cves: List[str]) -> Dict[str, Any]:
        """Calculate temporal analysis showing trends over time."""
        year_counts = {}
        
        for cve_id in all_matched_cves:
            year_match = re.search(r'CVE-(\d{4})-', cve_id)
            if year_match:
                year = int(year_match.group(1))
                year_counts[year] = year_counts.get(year, 0) + 1
        
        # Sort by year
        sorted_years = sorted(year_counts.items())
        
        # Calculate trends
        recent_5_years = sum(count for year, count in sorted_years if year >= 2020)
        previous_5_years = sum(count for year, count in sorted_years if 2015 <= year < 2020)
        
        trend = "increasing" if recent_5_years > previous_5_years else "decreasing" if recent_5_years < previous_5_years else "stable"
        
        return {
            "years_breakdown": dict(sorted_years),
            "recent_5_years": recent_5_years,
            "previous_5_years": previous_5_years,
            "trend": trend,
            "peak_year": max(sorted_years, key=lambda x: x[1])[0] if sorted_years else None,
            "peak_year_count": max(sorted_years, key=lambda x: x[1])[1] if sorted_years else 0
        }
    
    def _generate_wildcard_recommendations(self, search_term: str, category_analyses: List[CategoryAnalysisResult], overall_metrics: Dict[str, Any]) -> List[str]:
        """Generate security recommendations for wildcard analysis."""
        recommendations = []
        
        if not category_analyses:
            return [f"No vulnerabilities found related to '{search_term}'"]
        
        # Overall risk assessment
        total_cves = overall_metrics.get("total_matched_cves", 0)
        exploitation_risk = overall_metrics.get("exploitation_risk", 0.0)
        activity_rate = overall_metrics.get("vulnerability_activity_rate", 0.0)
        
        if exploitation_risk >= 0.15:
            recommendations.append(f"CRITICAL: '{search_term}' shows very high exploitation risk ({exploitation_risk:.1%}) - immediate security review required")
        elif exploitation_risk >= 0.08:
            recommendations.append(f"HIGH: '{search_term}' has elevated exploitation risk ({exploitation_risk:.1%}) - prioritize security measures")
        elif exploitation_risk >= 0.03:
            recommendations.append(f"MEDIUM: '{search_term}' has moderate exploitation risk ({exploitation_risk:.1%}) - monitor for updates")
        
        if activity_rate >= 2.5:
            recommendations.append(f"HIGH ACTIVITY: '{search_term}' shows significantly increased recent vulnerability activity - monitor closely")
        elif activity_rate >= 1.5:
            recommendations.append(f"INCREASED ACTIVITY: '{search_term}' has higher recent vulnerability activity than historical average")
        
        # Category-specific recommendations
        high_risk_categories = [cat for cat in category_analyses if cat.exploitation_risk >= 0.10]
        if high_risk_categories:
            recommendations.append(f"High-risk categories found: {', '.join([cat.category_name for cat in high_risk_categories])}")
            
            for cat in high_risk_categories[:3]:  # Top 3 high-risk categories
                top_match = cat.top_matches[0] if cat.top_matches else ("unknown", 0)
                recommendations.append(f"  - {cat.category_name}: '{top_match[0]}' has {top_match[1]} CVEs with {cat.exploitation_risk:.1%} exploitation risk")
        
        # Volume-based recommendations
        if total_cves >= 1000:
            recommendations.append(f"LARGE VOLUME: Found {total_cves} CVEs related to '{search_term}' - consider focusing on most critical vulnerabilities")
        elif total_cves >= 100:
            recommendations.append(f"SIGNIFICANT VOLUME: Found {total_cves} CVEs related to '{search_term}' - systematic review recommended")
        
        # Temporal recommendations
        trend = overall_metrics.get("trend", "unknown")
        if trend == "increasing":
            recommendations.append(f"TREND ALERT: Vulnerability reports for '{search_term}' are increasing - enhance monitoring")
        
        return recommendations if recommendations else [f"'{search_term}' shows normal vulnerability patterns - continue standard monitoring"]
    
    def _convert_wildcard_to_analysis(self, wildcard_result: WildcardAnalysisResult) -> AnalysisResult:
        """Convert wildcard result to standard AnalysisResult for backward compatibility."""
        return AnalysisResult(
            identifier=wildcard_result.search_term,
            input_type="wildcard",
            matched_cves=wildcard_result.total_matched_cves[:100],  # Limit for performance
            introduction_rate=wildcard_result.overall_metrics.get("vulnerability_activity_rate", 0.0),
            history_usage_rate=wildcard_result.overall_metrics.get("exploitation_risk", 0.0),
            analysis_period="Comprehensive database search",
            total_cves_analyzed=len(wildcard_result.total_matched_cves),
            vulnerability_activity_rate=wildcard_result.overall_metrics.get("vulnerability_activity_rate"),
            exploitation_risk=wildcard_result.overall_metrics.get("exploitation_risk"),
            relative_threat_level=wildcard_result.overall_metrics.get("relative_threat_level"),
            metadata={
                "search_term": wildcard_result.search_term,
                "categories_found": len(wildcard_result.category_analyses),
                "temporal_analysis": wildcard_result.temporal_analysis,
                "recommendations": wildcard_result.recommendations[:5],  # Top 5 recommendations
                "risk_summary": {
                    "overall_metrics": wildcard_result.overall_metrics,
                    "category_summary": [
                        {
                            "category": cat.category_name,
                            "cves": cat.total_cves,
                            "matches": cat.unique_matches,
                            "exploitation_risk": cat.exploitation_risk
                        }
                        for cat in wildcard_result.category_analyses
                    ]
                }
            }
        ) 