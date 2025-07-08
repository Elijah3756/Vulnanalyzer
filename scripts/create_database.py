#!/usr/bin/env python3
"""
Create and populate a SQLite database with CVE data and known exploited vulnerabilities.
This provides fast querying capabilities for the vulnerability analyzer.
"""

import json
import logging
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import argparse

from tqdm import tqdm


class CVEDatabaseBuilder:
    """Builds and manages a SQLite database of CVE data."""
    
    def __init__(self, db_path: str = "cve_database.db", verbose: bool = False):
        """Initialize the database builder."""
        self.db_path = Path(db_path)
        self.verbose = verbose
        self.logger = self._setup_logger()
        self.conn: Optional[sqlite3.Connection] = None
        
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
    
    def connect(self) -> None:
        """Connect to the SQLite database."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row  # Enable dict-like access
        
        # Enable foreign keys and optimize for bulk inserts
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA synchronous = OFF")
        self.conn.execute("PRAGMA journal_mode = MEMORY")
        self.conn.execute("PRAGMA cache_size = 10000")
    
    def disconnect(self) -> None:
        """Disconnect from the database."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def create_schema(self) -> None:
        """Create the database schema."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        self.logger.info("Creating database schema...")
        
        # CVE Records table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_records (
                cve_id TEXT PRIMARY KEY,
                year INTEGER NOT NULL,
                published_date TEXT,
                updated_date TEXT,
                state TEXT,
                assigner_org_id TEXT,
                assigner_short_name TEXT,
                data_version TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # CVE Descriptions table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_descriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                lang TEXT NOT NULL,
                value TEXT NOT NULL,
                FOREIGN KEY (cve_id) REFERENCES cve_records (cve_id) ON DELETE CASCADE
            )
        """)
        
        # CVE Affected Products table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_affected (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                vendor TEXT,
                product TEXT,
                version TEXT,
                version_status TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve_records (cve_id) ON DELETE CASCADE
            )
        """)
        
        # CVE References table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_references (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                url TEXT NOT NULL,
                tags TEXT,  -- JSON array as text
                FOREIGN KEY (cve_id) REFERENCES cve_records (cve_id) ON DELETE CASCADE
            )
        """)
        
        # CVE Problem Types table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_problem_types (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cve_id TEXT NOT NULL,
                lang TEXT,
                description TEXT,
                type TEXT,
                FOREIGN KEY (cve_id) REFERENCES cve_records (cve_id) ON DELETE CASCADE
            )
        """)
        
        # CISA Known Exploited Vulnerabilities table
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS known_exploited_vulns (
                cve_id TEXT PRIMARY KEY,
                vendor_project TEXT,
                product TEXT,
                vulnerability_name TEXT,
                date_added TEXT,
                short_description TEXT,
                required_action TEXT,
                due_date TEXT,
                known_ransomware_campaign_use TEXT,
                notes TEXT,
                cwes TEXT,  -- JSON array as text
                catalog_version TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # CVE Search Index (for full-text search)
        self.conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS cve_search USING fts5(
                cve_id,
                vendor,
                product,
                description,
                problem_types
            )
        """)
        
        # Create indexes for performance
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_year ON cve_records (year)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_published ON cve_records (published_date)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_state ON cve_records (state)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_affected_vendor ON cve_affected (vendor)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_affected_product ON cve_affected (product)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_references_url ON cve_references (url)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_kev_date_added ON known_exploited_vulns (date_added)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_kev_vendor ON known_exploited_vulns (vendor_project)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_kev_product ON known_exploited_vulns (product)")
        
        self.conn.commit()
        self.logger.info("Database schema created successfully")
    
    def clear_database(self) -> None:
        """Clear all data from the database."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        self.logger.info("Clearing existing data...")
        
        tables = [
            'cve_search',
            'known_exploited_vulns',
            'cve_problem_types',
            'cve_references',
            'cve_affected',
            'cve_descriptions',
            'cve_records'
        ]
        
        for table in tables:
            self.conn.execute(f"DELETE FROM {table}")
        
        self.conn.commit()
        self.logger.info("Database cleared")
    
    def insert_cve_record(self, cve_data: Dict[str, Any]) -> bool:
        """Insert a CVE record into the database."""
        try:
            # Extract metadata
            cve_metadata = cve_data.get("cveMetadata", {})
            cve_id = cve_metadata.get("cveId", "")
            
            if not cve_id:
                return False
            
            # Extract year from CVE ID
            year = int(cve_id.split("-")[1]) if "-" in cve_id else 0
            
            # Insert main CVE record
            self.conn.execute("""
                INSERT OR REPLACE INTO cve_records 
                (cve_id, year, published_date, updated_date, state, assigner_org_id, 
                 assigner_short_name, data_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                year,
                cve_metadata.get("datePublished"),
                cve_metadata.get("dateUpdated"),
                cve_metadata.get("state"),
                cve_metadata.get("assignerOrgId"),
                cve_metadata.get("assignerShortName"),
                cve_data.get("dataVersion")
            ))
            
            # Get CNA container data
            cna_data = cve_data.get("containers", {}).get("cna", {})
            
            # Insert descriptions
            descriptions = cna_data.get("descriptions", [])
            for desc in descriptions:
                self.conn.execute("""
                    INSERT INTO cve_descriptions (cve_id, lang, value)
                    VALUES (?, ?, ?)
                """, (cve_id, desc.get("lang"), desc.get("value")))
            
            # Insert affected products
            affected = cna_data.get("affected", [])
            for affect in affected:
                vendor = affect.get("vendor", "n/a")
                product = affect.get("product", "n/a")
                versions = affect.get("versions", [])
                
                if not versions:
                    # Insert without version info
                    self.conn.execute("""
                        INSERT INTO cve_affected (cve_id, vendor, product)
                        VALUES (?, ?, ?)
                    """, (cve_id, vendor, product))
                else:
                    # Insert each version
                    for version in versions:
                        self.conn.execute("""
                            INSERT INTO cve_affected 
                            (cve_id, vendor, product, version, version_status)
                            VALUES (?, ?, ?, ?, ?)
                        """, (
                            cve_id, vendor, product,
                            version.get("version"),
                            version.get("status")
                        ))
            
            # Insert references
            references = cna_data.get("references", [])
            for ref in references:
                self.conn.execute("""
                    INSERT INTO cve_references (cve_id, url, tags)
                    VALUES (?, ?, ?)
                """, (
                    cve_id,
                    ref.get("url"),
                    json.dumps(ref.get("tags", []))
                ))
            
            # Insert problem types
            problem_types = cna_data.get("problemTypes", [])
            for pt in problem_types:
                for desc in pt.get("descriptions", []):
                    self.conn.execute("""
                        INSERT INTO cve_problem_types 
                        (cve_id, lang, description, type)
                        VALUES (?, ?, ?, ?)
                    """, (
                        cve_id,
                        desc.get("lang"),
                        desc.get("description"),
                        desc.get("type")
                    ))
            
            # Insert into search index
            search_description = " ".join([d.get("value", "") for d in descriptions])
            search_problem_types = " ".join([
                desc.get("description", "")
                for pt in problem_types
                for desc in pt.get("descriptions", [])
            ])
            
            # Get primary vendor/product for search
            primary_vendor = affected[0].get("vendor", "") if affected else ""
            primary_product = affected[0].get("product", "") if affected else ""
            
            self.conn.execute("""
                INSERT INTO cve_search 
                (cve_id, vendor, product, description, problem_types)
                VALUES (?, ?, ?, ?, ?)
            """, (
                cve_id,
                primary_vendor,
                primary_product,
                search_description,
                search_problem_types
            ))
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error inserting CVE {cve_id}: {str(e)}")
            return False
    
    def load_cve_files(self, cve_dir: Path) -> None:
        """Load all CVE files from the directory structure."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        self.logger.info(f"Loading CVE files from {cve_dir}")
        
        # Count total files first
        total_files = 0
        for year_dir in cve_dir.iterdir():
            if year_dir.is_dir() and year_dir.name.isdigit():
                for subdir in year_dir.iterdir():
                    if subdir.is_dir():
                        total_files += len(list(subdir.glob("*.json")))
        
        self.logger.info(f"Found {total_files} CVE files to process")
        
        # Process files with progress bar
        processed = 0
        errors = 0
        
        with tqdm(total=total_files, desc="Loading CVEs") as pbar:
            for year_dir in sorted(cve_dir.iterdir()):
                if not (year_dir.is_dir() and year_dir.name.isdigit()):
                    continue
                
                for subdir in sorted(year_dir.iterdir()):
                    if not subdir.is_dir():
                        continue
                    
                    # Process files in batches for better performance
                    batch_size = 1000
                    files = list(subdir.glob("*.json"))
                    
                    for i in range(0, len(files), batch_size):
                        batch = files[i:i + batch_size]
                        
                        # Start transaction for batch
                        self.conn.execute("BEGIN TRANSACTION")
                        
                        try:
                            for cve_file in batch:
                                try:
                                    with open(cve_file, 'r', encoding='utf-8') as f:
                                        cve_data = json.load(f)
                                    
                                    if self.insert_cve_record(cve_data):
                                        processed += 1
                                    else:
                                        errors += 1
                                        
                                except Exception as e:
                                    self.logger.error(f"Error processing {cve_file}: {str(e)}")
                                    errors += 1
                                
                                pbar.update(1)
                            
                            # Commit batch
                            self.conn.execute("COMMIT")
                            
                        except Exception as e:
                            self.conn.execute("ROLLBACK")
                            self.logger.error(f"Batch processing error: {str(e)}")
                            errors += len(batch)
        
        self.logger.info(f"CVE loading completed: {processed} processed, {errors} errors")
    
    def load_known_exploited_vulns(self, kev_file: Path) -> None:
        """Load known exploited vulnerabilities from CISA catalog."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        self.logger.info(f"Loading known exploited vulnerabilities from {kev_file}")
        
        try:
            with open(kev_file, 'r', encoding='utf-8') as f:
                kev_data = json.load(f)
            
            catalog_version = kev_data.get("catalogVersion", "")
            vulnerabilities = kev_data.get("vulnerabilities", [])
            
            self.logger.info(f"Found {len(vulnerabilities)} known exploited vulnerabilities")
            
            processed = 0
            errors = 0
            
            # Process in batches
            batch_size = 100
            for i in tqdm(range(0, len(vulnerabilities), batch_size), desc="Loading KEVs"):
                batch = vulnerabilities[i:i + batch_size]
                
                self.conn.execute("BEGIN TRANSACTION")
                
                try:
                    for vuln in batch:
                        try:
                            self.conn.execute("""
                                INSERT OR REPLACE INTO known_exploited_vulns
                                (cve_id, vendor_project, product, vulnerability_name,
                                 date_added, short_description, required_action, due_date,
                                 known_ransomware_campaign_use, notes, cwes, catalog_version)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                vuln.get("cveID"),
                                vuln.get("vendorProject"),
                                vuln.get("product"),
                                vuln.get("vulnerabilityName"),
                                vuln.get("dateAdded"),
                                vuln.get("shortDescription"),
                                vuln.get("requiredAction"),
                                vuln.get("dueDate"),
                                vuln.get("knownRansomwareCampaignUse"),
                                vuln.get("notes"),
                                json.dumps(vuln.get("cwes", [])),
                                catalog_version
                            ))
                            processed += 1
                            
                        except Exception as e:
                            self.logger.error(f"Error inserting KEV {vuln.get('cveID')}: {str(e)}")
                            errors += 1
                    
                    self.conn.execute("COMMIT")
                    
                except Exception as e:
                    self.conn.execute("ROLLBACK")
                    self.logger.error(f"KEV batch processing error: {str(e)}")
                    errors += len(batch)
            
            self.logger.info(f"KEV loading completed: {processed} processed, {errors} errors")
            
        except Exception as e:
            self.logger.error(f"Error loading KEV file: {str(e)}")
    
    def create_summary_views(self) -> None:
        """Create database views for common queries."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        self.logger.info("Creating summary views...")
        
        # CVE summary view
        self.conn.execute("""
            CREATE VIEW IF NOT EXISTS cve_summary AS
            SELECT 
                c.cve_id,
                c.year,
                c.published_date,
                c.state,
                GROUP_CONCAT(DISTINCT a.vendor) as vendors,
                GROUP_CONCAT(DISTINCT a.product) as products,
                GROUP_CONCAT(DISTINCT d.value, ' | ') as descriptions,
                COUNT(DISTINCT r.url) as reference_count,
                CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_known_exploited
            FROM cve_records c
            LEFT JOIN cve_affected a ON c.cve_id = a.cve_id
            LEFT JOIN cve_descriptions d ON c.cve_id = d.cve_id AND d.lang = 'en'
            LEFT JOIN cve_references r ON c.cve_id = r.cve_id
            LEFT JOIN known_exploited_vulns k ON c.cve_id = k.cve_id
            GROUP BY c.cve_id
        """)
        
        # Known exploited summary view
        self.conn.execute("""
            CREATE VIEW IF NOT EXISTS kev_summary AS
            SELECT 
                k.*,
                c.published_date as cve_published_date,
                c.year as cve_year
            FROM known_exploited_vulns k
            LEFT JOIN cve_records c ON k.cve_id = c.cve_id
        """)
        
        # Vulnerability statistics view
        self.conn.execute("""
            CREATE VIEW IF NOT EXISTS vuln_stats AS
            SELECT 
                'Total CVEs' as metric,
                COUNT(*) as count
            FROM cve_records
            UNION ALL
            SELECT 
                'Known Exploited' as metric,
                COUNT(*) as count
            FROM known_exploited_vulns
            UNION ALL
            SELECT 
                'CVEs by Year' as metric,
                year || ': ' || COUNT(*) as count
            FROM cve_records
            GROUP BY year
            ORDER BY metric, count DESC
        """)
        
        self.conn.commit()
        self.logger.info("Summary views created")
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        stats = {}
        
        # Basic counts
        cursor = self.conn.execute("SELECT COUNT(*) FROM cve_records")
        stats['total_cves'] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM known_exploited_vulns")
        stats['known_exploited'] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT MIN(year), MAX(year) FROM cve_records")
        min_year, max_year = cursor.fetchone()
        stats['year_range'] = f"{min_year}-{max_year}"
        
        # CVEs by year
        cursor = self.conn.execute("""
            SELECT year, COUNT(*) 
            FROM cve_records 
            GROUP BY year 
            ORDER BY year DESC 
            LIMIT 10
        """)
        stats['recent_years'] = dict(cursor.fetchall())
        
        # Top vendors
        cursor = self.conn.execute("""
            SELECT vendor, COUNT(*) as count
            FROM cve_affected 
            WHERE vendor != 'n/a' AND vendor IS NOT NULL
            GROUP BY vendor 
            ORDER BY count DESC 
            LIMIT 10
        """)
        stats['top_vendors'] = dict(cursor.fetchall())
        
        # Database size
        cursor = self.conn.execute("PRAGMA page_count")
        page_count = cursor.fetchone()[0]
        cursor = self.conn.execute("PRAGMA page_size")
        page_size = cursor.fetchone()[0]
        stats['db_size_mb'] = round((page_count * page_size) / (1024 * 1024), 2)
        
        return stats


def main():
    """Main function for the database builder."""
    parser = argparse.ArgumentParser(description="Create CVE database from files")
    parser.add_argument(
        "--cve-dir",
        type=Path,
        default="./cvelistV5/cves",
        help="CVE data directory"
    )
    parser.add_argument(
        "--kev-file",
        type=Path,
        default="./known_exploited_vulnerabilities.json",
        help="Known exploited vulnerabilities JSON file"
    )
    parser.add_argument(
        "--db-path",
        default="cve_database.db",
        help="Output database path"
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear existing database"
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="Show database statistics only"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Initialize database builder
    builder = CVEDatabaseBuilder(args.db_path, args.verbose)
    
    try:
        builder.connect()
        
        if args.stats_only:
            # Show statistics only
            stats = builder.get_database_stats()
            print("\n=== CVE Database Statistics ===")
            print(f"Database: {args.db_path}")
            print(f"Total CVEs: {stats['total_cves']:,}")
            print(f"Known Exploited: {stats['known_exploited']:,}")
            print(f"Year Range: {stats['year_range']}")
            print(f"Database Size: {stats['db_size_mb']} MB")
            
            print("\nRecent Years:")
            for year, count in stats['recent_years'].items():
                print(f"  {year}: {count:,} CVEs")
            
            print("\nTop Vendors:")
            for vendor, count in list(stats['top_vendors'].items())[:5]:
                print(f"  {vendor}: {count:,} CVEs")
            
            return
        
        # Create schema
        builder.create_schema()
        
        if args.clear:
            builder.clear_database()
        
        # Load CVE data
        if args.cve_dir.exists():
            start_time = time.time()
            builder.load_cve_files(args.cve_dir)
            cve_time = time.time() - start_time
            print(f"CVE loading completed in {cve_time:.1f} seconds")
        else:
            print(f"CVE directory not found: {args.cve_dir}")
        
        # Load known exploited vulnerabilities
        if args.kev_file.exists():
            start_time = time.time()
            builder.load_known_exploited_vulns(args.kev_file)
            kev_time = time.time() - start_time
            print(f"KEV loading completed in {kev_time:.1f} seconds")
        else:
            print(f"KEV file not found: {args.kev_file}")
        
        # Create summary views
        builder.create_summary_views()
        
        # Show final statistics
        stats = builder.get_database_stats()
        print("\n=== Database Created Successfully ===")
        print(f"Database: {args.db_path}")
        print(f"Total CVEs: {stats['total_cves']:,}")
        print(f"Known Exploited: {stats['known_exploited']:,}")
        print(f"Database Size: {stats['db_size_mb']} MB")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1
    
    finally:
        builder.disconnect()
    
    return 0


if __name__ == "__main__":
    exit(main()) 