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
        
        # Retry configuration
        self.max_retries = 3
        self.retry_delay_base = 60 if api_key else 120  # Base delay in seconds
        self.max_retry_delay = 600  # Maximum delay in seconds
        
        # Setup logging
        self.logger = self._setup_logger()
        
        # Track requests for rate limiting
        self.request_times = []
        
        # Track download statistics
        self.download_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'rate_limit_hits': 0,
            'retries': 0
        }
    
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
    
    def _make_request(self, params: Dict[str, Any], max_retries: int = None) -> Optional[Dict[str, Any]]:
        """Make a request to the NVD API with rate limiting and retry logic."""
        if max_retries is None:
            max_retries = self.max_retries
            
        self._rate_limit_check()
        self.download_stats['total_requests'] += 1
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        
        for attempt in range(max_retries + 1):
            try:
                response = requests.get(
                    self.base_url,
                    params=params,
                    headers=headers,
                    timeout=30
                )
                
                # Handle 429 Too Many Requests
                if response.status_code == 429:
                    self.download_stats['rate_limit_hits'] += 1
                    if attempt < max_retries:
                        self.download_stats['retries'] += 1
                        # Exponential backoff: 2^attempt * base_delay
                        delay = min(self.retry_delay_base * (2 ** attempt), self.max_retry_delay)
                        
                        self.logger.warning(f"Rate limit exceeded (429). Retrying in {delay} seconds... (attempt {attempt + 1}/{max_retries + 1})")
                        time.sleep(delay)
                        
                        # Reset rate limit tracking after a 429
                        self.request_times = []
                        continue
                    else:
                        self.download_stats['failed_requests'] += 1
                        self.logger.error("Max retries exceeded for rate limit. Consider using an API key or waiting longer.")
                        return None
                
                # Handle other HTTP errors
                if response.status_code >= 400:
                    self.logger.error(f"HTTP {response.status_code}: {response.text}")
                    if response.status_code == 403:
                        self.logger.error("403 Forbidden - Check your API key if using one")
                    elif response.status_code == 500:
                        if attempt < max_retries:
                            self.download_stats['retries'] += 1
                            delay = 30 * (2 ** attempt)  # Exponential backoff for server errors
                            self.logger.warning(f"Server error (500). Retrying in {delay} seconds...")
                            time.sleep(delay)
                            continue
                    self.download_stats['failed_requests'] += 1
                    return None
                
                response.raise_for_status()
                self.download_stats['successful_requests'] += 1
                return response.json()
            
            except requests.exceptions.Timeout:
                if attempt < max_retries:
                    self.download_stats['retries'] += 1
                    delay = 30 * (2 ** attempt)
                    self.logger.warning(f"Request timeout. Retrying in {delay} seconds... (attempt {attempt + 1}/{max_retries + 1})")
                    time.sleep(delay)
                    continue
                else:
                    self.logger.error("Request timeout after all retries")
                    self.download_stats['failed_requests'] += 1
                    return None
            
            except requests.exceptions.ConnectionError:
                if attempt < max_retries:
                    self.download_stats['retries'] += 1
                    delay = 60 * (2 ** attempt)
                    self.logger.warning(f"Connection error. Retrying in {delay} seconds... (attempt {attempt + 1}/{max_retries + 1})")
                    time.sleep(delay)
                    continue
                else:
                    self.logger.error("Connection error after all retries")
                    self.download_stats['failed_requests'] += 1
                    return None
            
            except requests.exceptions.RequestException as e:
                self.logger.error(f"API request failed: {e}")
                self.download_stats['failed_requests'] += 1
                return None
        
        self.download_stats['failed_requests'] += 1
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
    
    def get_download_stats(self) -> Dict[str, Any]:
        """Get download statistics."""
        stats = self.download_stats.copy()
        if stats['total_requests'] > 0:
            stats['success_rate'] = stats['successful_requests'] / stats['total_requests']
            stats['failure_rate'] = stats['failed_requests'] / stats['total_requests']
        else:
            stats['success_rate'] = 0.0
            stats['failure_rate'] = 0.0
        return stats
    
    def reset_download_stats(self) -> None:
        """Reset download statistics."""
        self.download_stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'rate_limit_hits': 0,
            'retries': 0
        }
    
    def download_all_cves(self, results_per_page: int = 2000) -> List[Dict[str, Any]]:
        """
        Download ALL CVEs from the NVD database with enhanced error handling.
        
        Args:
            results_per_page: Number of results per API call (max 2000)
            
        Returns:
            List of CVE records
        """
        all_cves = []
        start_index = 0
        consecutive_failures = 0
        max_consecutive_failures = 5
        
        self.logger.info("Downloading ALL CVEs from NVD database...")
        self.reset_download_stats()
        
        while True:
            params = {
                "startIndex": start_index,
                "resultsPerPage": results_per_page
            }
            
            self.logger.info(f"Fetching results {start_index} to {start_index + results_per_page}")
            
            response_data = self._make_request(params)
            if not response_data:
                consecutive_failures += 1
                self.logger.error(f"Failed to get response from NVD API (failure {consecutive_failures}/{max_consecutive_failures})")
                
                if consecutive_failures >= max_consecutive_failures:
                    self.logger.error(f"Too many consecutive failures ({consecutive_failures}). Stopping download.")
                    break
                
                # Wait longer between retries for consecutive failures
                wait_time = min(300 * consecutive_failures, 1800)  # 5-30 minutes
                self.logger.info(f"Waiting {wait_time} seconds before retrying...")
                time.sleep(wait_time)
                continue
            
            # Reset consecutive failures on success
            consecutive_failures = 0
            
            vulnerabilities = response_data.get("vulnerabilities", [])
            if not vulnerabilities:
                self.logger.info("No more vulnerabilities found")
                break
            
            all_cves.extend(vulnerabilities)
            
            # Check if we've got all results
            total_results = response_data.get("totalResults", 0)
            self.logger.info(f"Progress: {len(all_cves)} / {total_results} CVEs downloaded")
            
            # Log statistics periodically
            if len(all_cves) % 10000 == 0:
                stats = self.get_download_stats()
                self.logger.info(f"Download stats: {stats['successful_requests']} successful, "
                               f"{stats['failed_requests']} failed, {stats['rate_limit_hits']} rate limits, "
                               f"{stats['retries']} retries")
            
            if start_index + results_per_page >= total_results:
                break
            
            start_index += results_per_page
        
        # Final statistics
        stats = self.get_download_stats()
        self.logger.info(f"Download completed: {len(all_cves)} total CVEs")
        self.logger.info(f"Final stats: {stats['successful_requests']} successful requests, "
                        f"{stats['failed_requests']} failed requests, {stats['rate_limit_hits']} rate limit hits, "
                        f"{stats['retries']} retries, {stats['success_rate']:.1%} success rate")
        
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
        default=os.getenv('DOWNLOAD_DIR', "downloaded_cves"),
        help=f"Output directory for CVE data (default: $DOWNLOAD_DIR or downloaded_cves)"
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
    parser.add_argument(
        "--max-retries",
        type=int,
        default=3,
        help="Maximum number of retries for failed requests (default: 3)"
    )
    parser.add_argument(
        "--retry-delay",
        type=int,
        default=60,
        help="Base delay in seconds for retries (default: 60, longer without API key)"
    )
    parser.add_argument(
        "--max-retry-delay",
        type=int,
        default=600,
        help="Maximum delay in seconds for retries (default: 600)"
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Initialize downloader with custom retry settings
    downloader = NVDDownloader(
        api_key=args.api_key,
        output_dir=args.output_dir
    )
    
    # Override retry settings if provided
    if args.max_retries is not None:
        downloader.max_retries = args.max_retries
    if args.retry_delay is not None:
        downloader.retry_delay_base = args.retry_delay if args.api_key else args.retry_delay * 2
    if args.max_retry_delay is not None:
        downloader.max_retry_delay = args.max_retry_delay
    
    # Set verbose logging if requested
    if args.verbose:
        downloader.logger.setLevel(logging.INFO)
    
    print(f"Starting CVE download with settings:")
    print(f"  API Key: {'Yes' if args.api_key else 'No'}")
    print(f"  Max Retries: {downloader.max_retries}")
    print(f"  Base Retry Delay: {downloader.retry_delay_base}s")
    print(f"  Max Retry Delay: {downloader.max_retry_delay}s")
    print(f"  Rate Limit: {downloader.rate_limit} requests per {downloader.rate_window}s")
    print()
    
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
    
    # Print final statistics
    stats = downloader.get_download_stats()
    print(f"\nDownload completed!")
    print(f"Statistics:")
    print(f"  Total Requests: {stats['total_requests']}")
    print(f"  Successful: {stats['successful_requests']}")
    print(f"  Failed: {stats['failed_requests']}")
    print(f"  Rate Limit Hits: {stats['rate_limit_hits']}")
    print(f"  Retries: {stats['retries']}")
    print(f"  Success Rate: {stats['success_rate']:.1%}")


if __name__ == "__main__":
    main() 