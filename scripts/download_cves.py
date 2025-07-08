#!/usr/bin/env python3
"""
Script to download CVE data from the NVD (National Vulnerability Database) API.
This script fetches vulnerability data and saves it in a format compatible with
the vulnerability analyzer.
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


class NVDDownloader:
    """Downloads CVE data from the NVD API."""
    
    def __init__(self, api_key: Optional[str] = None, output_dir: str = "downloaded_cves"):
        """
        Initialize the NVD downloader.
        
        Args:
            api_key: Optional NVD API key for higher rate limits
            output_dir: Directory to save downloaded CVE data
        """
        self.api_key = api_key
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # API endpoints
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Rate limiting (without API key: 5 requests per 30 seconds)
        # With API key: 50 requests per 30 seconds
        self.rate_limit = 50 if api_key else 5
        self.rate_window = 30  # seconds
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # Track requests for rate limiting
        self.request_times = []
    
    def _setup_logger(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
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
    
    def _make_request(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make a request to the NVD API with rate limiting."""
        self._rate_limit_check()
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        try:
            response = requests.get(
                self.base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {e}")
            return None
    
    def download_cves_by_date_range(
        self,
        start_date: str,
        end_date: str,
        results_per_page: int = 2000
    ) -> List[Dict[str, Any]]:
        """
        Download CVEs within a date range.
        
        Args:
            start_date: Start date in YYYY-MM-DD format
            end_date: End date in YYYY-MM-DD format
            results_per_page: Number of results per API call (max 2000)
            
        Returns:
            List of CVE records
        """
        all_cves = []
        start_index = 0
        
        self.logger.info(f"Downloading CVEs from {start_date} to {end_date}")
        
        while True:
            params = {
                "pubStartDate": f"{start_date}T00:00:00.000",
                "pubEndDate": f"{end_date}T23:59:59.999",
                "startIndex": start_index,
                "resultsPerPage": results_per_page
            }
            
            self.logger.info(f"Fetching results {start_index} to {start_index + results_per_page}")
            
            response_data = self._make_request(params)
            if not response_data:
                break
            
            vulnerabilities = response_data.get("vulnerabilities", [])
            if not vulnerabilities:
                break
            
            all_cves.extend(vulnerabilities)
            
            # Check if we've got all results
            total_results = response_data.get("totalResults", 0)
            if start_index + results_per_page >= total_results:
                break
            
            start_index += results_per_page
        
        self.logger.info(f"Downloaded {len(all_cves)} CVEs")
        return all_cves
    
    def download_recent_cves(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Download CVEs from the last N days.
        
        Args:
            days: Number of days to look back
            
        Returns:
            List of CVE records
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        
        return self.download_cves_by_date_range(
            start_date.strftime("%Y-%m-%d"),
            end_date.strftime("%Y-%m-%d")
        )
    
    def download_cves_by_year(self, year: int) -> List[Dict[str, Any]]:
        """
        Download all CVEs for a specific year.
        
        Args:
            year: Year to download CVEs for
            
        Returns:
            List of CVE records
        """
        start_date = f"{year}-01-01"
        end_date = f"{year}-12-31"
        
        return self.download_cves_by_date_range(start_date, end_date)
    
    def save_cves_to_files(self, cves: List[Dict[str, Any]]) -> None:
        """
        Save CVE data to individual JSON files organized by year.
        
        Args:
            cves: List of CVE records to save
        """
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
                year_dir = self.output_dir / year
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
        """
        Convert NVD API response to CVE Record Format 5.x structure.
        
        Args:
            nvd_data: Raw data from NVD API
            
        Returns:
            CVE record in v5.x format
        """
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
    
    def download_all_cves(self, results_per_page: int = 2000) -> List[Dict[str, Any]]:
        """
        Download ALL CVEs from the NVD database.
        
        Args:
            results_per_page: Number of results per API call (max 2000)
            
        Returns:
            List of CVE records
        """
        all_cves = []
        start_index = 0
        
        self.logger.info("Downloading ALL CVEs from NVD database...")
        
        while True:
            params = {
                "startIndex": start_index,
                "resultsPerPage": results_per_page
            }
            
            self.logger.info(f"Fetching results {start_index} to {start_index + results_per_page}")
            
            response_data = self._make_request(params)
            if not response_data:
                self.logger.error("Failed to get response from NVD API")
                break
            
            vulnerabilities = response_data.get("vulnerabilities", [])
            if not vulnerabilities:
                self.logger.info("No more vulnerabilities found")
                break
            
            all_cves.extend(vulnerabilities)
            
            # Check if we've got all results
            total_results = response_data.get("totalResults", 0)
            self.logger.info(f"Progress: {len(all_cves)} / {total_results} CVEs downloaded")
            
            if start_index + results_per_page >= total_results:
                break
            
            start_index += results_per_page
        
        self.logger.info(f"Downloaded {len(all_cves)} total CVEs")
        return all_cves
    
    def download_and_save_all(self) -> None:
        """Download and save ALL CVEs from the NVD database."""
        cves = self.download_all_cves()
        if cves:
            self.save_cves_to_files(cves)
        else:
            self.logger.error("No CVEs downloaded")
    
    def download_and_save_by_year(self, year: int) -> None:
        """Download and save all CVEs for a specific year."""
        cves = self.download_cves_by_year(year)
        if cves:
            self.save_cves_to_files(cves)
    
    def download_and_save_recent(self, days: int = 30) -> None:
        """Download and save recent CVEs."""
        cves = self.download_recent_cves(days)
        if cves:
            self.save_cves_to_files(cves)


def main():
    """Main function to run the CVE downloader."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Download CVE data from NVD API")
    parser.add_argument(
        "--api-key",
        help="NVD API key (optional, but recommended for higher rate limits)"
    )
    parser.add_argument(
        "--output-dir",
        default="downloaded_cves",
        help="Output directory for CVE data"
    )
    parser.add_argument(
        "--year",
        type=int,
        help="Download CVEs for a specific year"
    )
    parser.add_argument(
        "--recent-days",
        type=int,
        default=30,
        help="Download CVEs from the last N days"
    )
    parser.add_argument(
        "--start-date",
        help="Start date (YYYY-MM-DD) for custom date range"
    )
    parser.add_argument(
        "--end-date",
        help="End date (YYYY-MM-DD) for custom date range"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Download ALL CVEs from the NVD database"
    )
    
    args = parser.parse_args()
    
    # Initialize downloader
    downloader = NVDDownloader(
        api_key=args.api_key,
        output_dir=args.output_dir
    )
    
    if args.year:
        print(f"Downloading CVEs for year {args.year}")
        downloader.download_and_save_by_year(args.year)
    elif args.start_date and args.end_date:
        print(f"Downloading CVEs from {args.start_date} to {args.end_date}")
        cves = downloader.download_cves_by_date_range(args.start_date, args.end_date)
        downloader.save_cves_to_files(cves)
    elif args.all:
        print("Downloading ALL CVEs from NVD database...")
        downloader.download_and_save_all()
    else:
        print(f"Downloading CVEs from the last {args.recent_days} days")
        downloader.download_and_save_recent(args.recent_days)


if __name__ == "__main__":
    main() 