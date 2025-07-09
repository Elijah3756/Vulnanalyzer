"""
Database management for vulnerability analyzer.

Handles CVE data downloads, KEV data management, and database operations.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
import requests
from tqdm import tqdm

from .database import CVEDatabase


class DatabaseManager:
    """Manages vulnerability database operations including downloads and setup."""
    
    def __init__(self, database_path: Path, cve_data_path: Path, 
                 kev_file_path: Path, download_dir: Path, verbose: bool = False):
        """Initialize the database manager."""
        self.database_path = database_path
        self.cve_data_path = cve_data_path
        self.kev_file_path = kev_file_path
        self.download_dir = download_dir
        self.verbose = verbose
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # NVD API configuration
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        # Rate limiting
        self.rate_limit = 5  # requests per 30 seconds without API key
        self.rate_window = 30
        self.request_times = []
        
        # Create directories
        self._ensure_directories()
    
    def _setup_logger(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO if self.verbose else logging.WARNING)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def _ensure_directories(self) -> None:
        """Ensure all necessary directories exist."""
        for path in [self.database_path.parent, self.cve_data_path, self.download_dir]:
            path.mkdir(parents=True, exist_ok=True)
        
        # Ensure the parent directory of the KEV file exists, but not the file itself
        self.kev_file_path.parent.mkdir(parents=True, exist_ok=True)
    
    def _rate_limit_check(self) -> None:
        """Check and enforce rate limiting."""
        current_time = time.time()
        
        # Remove old requests outside the rate window
        self.request_times = [
            t for t in self.request_times 
            if current_time - t < self.rate_window
        ]
        
        # If we're at the rate limit, wait
        if len(self.request_times) >= self.rate_limit:
            sleep_time = self.rate_window - (current_time - self.request_times[0]) + 1
            if sleep_time > 0:
                self.logger.info(f"Rate limit reached. Waiting {sleep_time:.1f} seconds...")
                time.sleep(sleep_time)
                self.request_times = []
        
        # Record this request
        self.request_times.append(current_time)
    
    def download_kev_data(self) -> None:
        """Download CISA Known Exploited Vulnerabilities catalog."""
        try:
            self.logger.info("Downloading CISA Known Exploited Vulnerabilities...")
            
            response = requests.get(self.kev_url, timeout=30)
            response.raise_for_status()
            
            kev_data = response.json()
            
            # Save to file
            with open(self.kev_file_path, 'w', encoding='utf-8') as f:
                json.dump(kev_data, f, indent=2, ensure_ascii=False)
            
            vulnerabilities = kev_data.get("vulnerabilities", [])
            self.logger.info(f"Downloaded {len(vulnerabilities)} known exploited vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Failed to download KEV data: {str(e)}")
            raise
    
    def download_cve_data(self, api_key: Optional[str] = None, 
                         recent_days: Optional[int] = None,
                         all_cves: bool = False) -> None:
        """Download CVE data from NVD API."""
        try:
            if api_key:
                self.rate_limit = 50  # Higher rate limit with API key
            
            if all_cves:
                self.logger.info("Downloading ALL CVEs from NVD (this will take several hours)...")
                self._download_all_cves(api_key)
            elif recent_days:
                self.logger.info(f"Downloading CVEs from the last {recent_days} days...")
                self._download_recent_cves(recent_days, api_key)
            else:
                self.logger.info("Downloading CVEs from the last 30 days...")
                self._download_recent_cves(30, api_key)
                
        except Exception as e:
            self.logger.error(f"Failed to download CVE data: {str(e)}")
            raise
    
    def _download_all_cves(self, api_key: Optional[str] = None) -> None:
        """Download all CVEs from NVD database."""
        all_cves = []
        start_index = 0
        results_per_page = 2000
        
        while True:
            self._rate_limit_check()
            
            params = {
                "startIndex": start_index,
                "resultsPerPage": results_per_page
            }
            
            headers = {}
            if api_key:
                headers["apiKey"] = api_key
            
            response = requests.get(
                self.nvd_base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 429:
                self.logger.warning("Rate limit exceeded. Waiting 60 seconds...")
                time.sleep(60)
                continue
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            
            all_cves.extend(vulnerabilities)
            
            total_results = data.get("totalResults", 0)
            self.logger.info(f"Progress: {len(all_cves)} / {total_results} CVEs downloaded")
            
            if start_index + results_per_page >= total_results:
                break
            
            start_index += results_per_page
        
        self._save_cves_to_files(all_cves)
    
    def _download_recent_cves(self, days: int, api_key: Optional[str] = None) -> None:
        """Download recent CVEs from NVD."""
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        all_cves = []
        start_index = 0
        results_per_page = 2000
        
        while True:
            self._rate_limit_check()
            
            params = {
                "pubStartDate": f"{start_date.strftime('%Y-%m-%d')}T00:00:00.000",
                "pubEndDate": f"{end_date.strftime('%Y-%m-%d')}T23:59:59.999",
                "startIndex": start_index,
                "resultsPerPage": results_per_page
            }
            
            headers = {}
            if api_key:
                headers["apiKey"] = api_key
            
            response = requests.get(
                self.nvd_base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 429:
                self.logger.warning("Rate limit exceeded. Waiting 60 seconds...")
                time.sleep(60)
                continue
            
            response.raise_for_status()
            data = response.json()
            
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            
            all_cves.extend(vulnerabilities)
            
            total_results = data.get("totalResults", 0)
            if start_index + results_per_page >= total_results:
                break
            
            start_index += results_per_page
        
        self._save_cves_to_files(all_cves)
    
    def _save_cves_to_files(self, cves: List[Dict[str, Any]]) -> None:
        """Save CVE data to individual JSON files organized by year."""
        self.logger.info(f"Saving {len(cves)} CVEs to files...")
        
        for cve_data in tqdm(cves, desc="Saving CVEs"):
            try:
                # Extract CVE information
                cve_record = cve_data.get("cve", {})
                cve_id = cve_record.get("id", "")
                
                if not cve_id:
                    continue
                
                # Extract year from CVE ID
                year = cve_id.split("-")[1] if "-" in cve_id else "unknown"
                
                # Create directory structure
                year_dir = self.cve_data_path / year
                year_dir.mkdir(parents=True, exist_ok=True)
                
                # Determine subdirectory based on CVE number
                cve_number = cve_id.split("-")[2] if len(cve_id.split("-")) > 2 else "0"
                if cve_number.isdigit():
                    # Group by thousands (e.g., 0xxx, 1xxx, 2xxx)
                    thousands = int(cve_number) // 1000
                    subdir = f"{thousands}xxx"
                else:
                    subdir = "0xxx"
                
                subdir_path = year_dir / subdir
                subdir_path.mkdir(parents=True, exist_ok=True)
                
                # Save to file
                file_path = subdir_path / f"{cve_id}.json"
                
                # Convert to CVE Record Format 5.x compatible structure
                cve_record_v5 = self._convert_to_cve_record_format(cve_data)
                
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(cve_record_v5, f, indent=2, ensure_ascii=False)
                    
            except Exception as e:
                self.logger.error(f"Error saving CVE {cve_id}: {e}")
                continue
        
        self.logger.info("CVE data saved successfully!")
    
    def _convert_to_cve_record_format(self, nvd_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert NVD API response to CVE Record Format 5.x structure."""
        cve_record = nvd_data.get("cve", {})
        cve_id = cve_record.get("id", "")
        
        # Extract publication dates
        published_date = cve_record.get("published", "")
        last_modified = cve_record.get("lastModified", "")
        
        # Extract descriptions
        descriptions = []
        for desc in cve_record.get("descriptions", []):
            if desc.get("lang") == "en":
                descriptions.append({
                    "lang": "en",
                    "value": desc.get("value", "")
                })
        
        # Extract affected products/vendors
        affected = []
        configurations = cve_record.get("configurations", [])
        
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    cpe_name = cpe_match.get("criteria", "")
                    if cpe_name.startswith("cpe:2.3:"):
                        parts = cpe_name.split(":")
                        if len(parts) >= 6:
                            vendor = parts[3] if parts[3] != "*" else "n/a"
                            product = parts[4] if parts[4] != "*" else "n/a"
                            version = parts[5] if parts[5] != "*" else "n/a"
                            
                            affected.append({
                                "vendor": vendor,
                                "product": product,
                                "versions": [{"version": version, "status": "affected"}]
                            })
        
        # Extract references
        references = []
        for ref in cve_record.get("references", []):
            references.append({
                "url": ref.get("url", ""),
                "tags": ref.get("tags", [])
            })
        
        # Extract problem types
        problem_types = []
        for weakness in cve_record.get("weaknesses", []):
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en":
                    problem_types.append({
                        "descriptions": [{
                            "lang": "en",
                            "type": "text",
                            "description": desc.get("value", "")
                        }]
                    })
        
        # Build CVE Record Format 5.x structure
        return {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.1",
            "cveMetadata": {
                "cveId": cve_id,
                "assignerOrgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",  # NVD
                "assignerShortName": "nvd",
                "datePublished": published_date,
                "dateUpdated": last_modified,
                "state": "PUBLISHED"
            },
            "containers": {
                "cna": {
                    "descriptions": descriptions,
                    "affected": affected,
                    "references": references,
                    "problemTypes": problem_types,
                    "providerMetadata": {
                        "orgId": "8254265b-2729-46b6-b9e3-3dfca2d5bfca",
                        "shortName": "nvd",
                        "dateUpdated": last_modified
                    }
                }
            }
        }
    
    def create_database(self) -> None:
        """Create the vulnerability database from CVE files."""
        try:
            self.logger.info("Creating vulnerability database...")
            
            # Import here to avoid circular imports
            import sys
            from pathlib import Path
            scripts_path = Path(__file__).parent.parent / 'scripts'
            sys.path.insert(0, str(scripts_path))
            from create_database import CVEDatabaseBuilder
            
            builder = CVEDatabaseBuilder(
                db_path=str(self.database_path),
                verbose=self.verbose
            )
            
            builder.connect()
            builder.create_schema()
            
            # Load CVE data
            if self.cve_data_path.exists():
                builder.load_cve_files(self.cve_data_path)
            
            # Load KEV data
            if self.kev_file_path.exists():
                builder.load_known_exploited_vulns(self.kev_file_path)
            
            # Create summary views
            builder.create_summary_views()
            
            # Show statistics
            stats = builder.get_database_stats()
            self.logger.info(f"Database created with {stats['total_cves']:,} CVEs and {stats['known_exploited']:,} KEVs")
            
            builder.disconnect()
            
        except Exception as e:
            self.logger.error(f"Failed to create database: {str(e)}")
            raise
    
    def update_database(self) -> None:
        """Update the existing database with new data."""
        try:
            self.logger.info("Updating vulnerability database...")
            
            # For now, rebuild the database with new data
            # In a production system, you might want incremental updates
            self.create_database()
            
        except Exception as e:
            self.logger.error(f"Failed to update database: {str(e)}")
            raise
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        try:
            if not self.database_path.exists():
                return {
                    "total_cves": 0,
                    "known_exploited": 0,
                    "db_size_mb": 0,
                    "year_range": "N/A"
                }
            
            with CVEDatabase(str(self.database_path)) as db:
                return db.get_database_stats()
                
        except Exception as e:
            self.logger.error(f"Failed to get database stats: {str(e)}")
            return {
                "total_cves": 0,
                "known_exploited": 0,
                "db_size_mb": 0,
                "year_range": "N/A"
            } 