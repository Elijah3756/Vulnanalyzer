#!/usr/bin/env python3
"""
Query the CVE database for analysis and research.
Provides various query options for the vulnerability database.
"""

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Any

from tabulate import tabulate


class CVEQueryTool:
    """Tool for querying the CVE database."""
    
    def __init__(self, db_path: str):
        """Initialize with database path."""
        self.db_path = Path(db_path)
        
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
        
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        stats = {}
        
        # Basic counts
        cursor = self.conn.execute("SELECT COUNT(*) FROM cve_records")
        stats['total_cves'] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM known_exploited_vulns")
        stats['known_exploited'] = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT MIN(year), MAX(year) FROM cve_records")
        min_year, max_year = cursor.fetchone()
        stats['year_range'] = f"{min_year}-{max_year}"
        
        # Database size
        cursor = self.conn.execute("PRAGMA page_count")
        page_count = cursor.fetchone()[0]
        cursor = self.conn.execute("PRAGMA page_size")
        page_size = cursor.fetchone()[0]
        stats['db_size_mb'] = round((page_count * page_size) / (1024 * 1024), 2)
        
        return stats
    
    def search_cve(self, cve_id: str) -> Dict[str, Any]:
        """Search for a specific CVE."""
        cursor = self.conn.execute("""
            SELECT c.*, 
                   GROUP_CONCAT(DISTINCT d.value, ' | ') as descriptions,
                   GROUP_CONCAT(DISTINCT a.vendor) as vendors,
                   GROUP_CONCAT(DISTINCT a.product) as products,
                   GROUP_CONCAT(DISTINCT pt.description) as problem_types,
                   COUNT(DISTINCT r.url) as reference_count,
                   CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_known_exploited,
                   k.vulnerability_name,
                   k.date_added as kev_date_added
            FROM cve_records c
            LEFT JOIN cve_descriptions d ON c.cve_id = d.cve_id AND d.lang = 'en'
            LEFT JOIN cve_affected a ON c.cve_id = a.cve_id
            LEFT JOIN cve_problem_types pt ON c.cve_id = pt.cve_id
            LEFT JOIN cve_references r ON c.cve_id = r.cve_id
            LEFT JOIN known_exploited_vulns k ON c.cve_id = k.cve_id
            WHERE c.cve_id = ?
            GROUP BY c.cve_id
        """, (cve_id.upper(),))
        
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def search_by_vendor(self, vendor: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search CVEs by vendor."""
        cursor = self.conn.execute("""
            SELECT c.cve_id, c.year, c.published_date,
                   a.vendor, a.product,
                   CASE WHEN k.cve_id IS NOT NULL THEN 'YES' ELSE 'NO' END as exploited
            FROM cve_records c
            JOIN cve_affected a ON c.cve_id = a.cve_id
            LEFT JOIN known_exploited_vulns k ON c.cve_id = k.cve_id
            WHERE a.vendor LIKE ?
            GROUP BY c.cve_id, c.year, c.published_date, a.vendor, a.product
            ORDER BY c.published_date DESC
            LIMIT ?
        """, (f"%{vendor}%", limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def search_by_product(self, product: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Search CVEs by product."""
        cursor = self.conn.execute("""
            SELECT c.cve_id, c.year, c.published_date,
                   a.vendor, a.product,
                   CASE WHEN k.cve_id IS NOT NULL THEN 'YES' ELSE 'NO' END as exploited
            FROM cve_records c
            JOIN cve_affected a ON c.cve_id = a.cve_id
            LEFT JOIN known_exploited_vulns k ON c.cve_id = k.cve_id
            WHERE a.product LIKE ?
            GROUP BY c.cve_id, c.year, c.published_date, a.vendor, a.product
            ORDER BY c.published_date DESC
            LIMIT ?
        """, (f"%{product}%", limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_known_exploited(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get known exploited vulnerabilities."""
        cursor = self.conn.execute("""
            SELECT k.cve_id, k.vendor_project, k.product, k.vulnerability_name,
                   k.date_added, c.year, c.published_date
            FROM known_exploited_vulns k
            LEFT JOIN cve_records c ON k.cve_id = c.cve_id
            ORDER BY k.date_added DESC
            LIMIT ?
        """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_year_stats(self, years: int = 10) -> List[Dict[str, Any]]:
        """Get CVE statistics by year."""
        cursor = self.conn.execute("""
            SELECT year, 
                   COUNT(*) as total_cves,
                   COUNT(k.cve_id) as known_exploited,
                   ROUND(COUNT(k.cve_id) * 100.0 / COUNT(*), 2) as exploit_rate
            FROM cve_records c
            LEFT JOIN known_exploited_vulns k ON c.cve_id = k.cve_id
            WHERE year >= (SELECT MAX(year) FROM cve_records) - ?
            GROUP BY year
            ORDER BY year DESC
        """, (years,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_top_vendors(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top vendors by CVE count."""
        cursor = self.conn.execute("""
            SELECT a.vendor, 
                   COUNT(*) as cve_count,
                   COUNT(k.cve_id) as exploited_count,
                   ROUND(COUNT(k.cve_id) * 100.0 / COUNT(*), 2) as exploit_rate
            FROM cve_affected a
            JOIN cve_records c ON a.cve_id = c.cve_id
            LEFT JOIN known_exploited_vulns k ON a.cve_id = k.cve_id
            WHERE a.vendor NOT IN ('n/a', '') AND a.vendor IS NOT NULL
            GROUP BY a.vendor
            ORDER BY cve_count DESC
            LIMIT ?
        """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def full_text_search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Full-text search across CVE data."""
        cursor = self.conn.execute("""
            SELECT s.cve_id, s.vendor, s.product, s.description,
                   c.year, c.published_date,
                   CASE WHEN k.cve_id IS NOT NULL THEN 'YES' ELSE 'NO' END as exploited
            FROM cve_search s
            JOIN cve_records c ON s.cve_id = c.cve_id
            LEFT JOIN known_exploited_vulns k ON s.cve_id = k.cve_id
            WHERE cve_search MATCH ?
            ORDER BY rank
            LIMIT ?
        """, (query, limit))
        
        return [dict(row) for row in cursor.fetchall()]


def print_table(data: List[Dict[str, Any]], headers: List[str] = None):
    """Print data as a formatted table."""
    if not data:
        print("No results found.")
        return
    
    if headers is None:
        headers = list(data[0].keys())
    
    table_data = [[row.get(h, '') for h in headers] for row in data]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))


def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(description="Query CVE database")
    parser.add_argument(
        "--db-path",
        default="cve_database.db",
        help="Path to CVE database"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show database statistics')
    
    # CVE search command
    cve_parser = subparsers.add_parser('cve', help='Search for specific CVE')
    cve_parser.add_argument('cve_id', help='CVE ID to search for')
    
    # Vendor search command
    vendor_parser = subparsers.add_parser('vendor', help='Search CVEs by vendor')
    vendor_parser.add_argument('vendor_name', help='Vendor name to search for')
    vendor_parser.add_argument('--limit', type=int, default=20, help='Limit results')
    
    # Product search command
    product_parser = subparsers.add_parser('product', help='Search CVEs by product')
    product_parser.add_argument('product_name', help='Product name to search for')
    product_parser.add_argument('--limit', type=int, default=20, help='Limit results')
    
    # Known exploited command
    kev_parser = subparsers.add_parser('kev', help='Show known exploited vulnerabilities')
    kev_parser.add_argument('--limit', type=int, default=20, help='Limit results')
    
    # Year stats command
    year_parser = subparsers.add_parser('years', help='Show statistics by year')
    year_parser.add_argument('--years', type=int, default=10, help='Number of years to show')
    
    # Top vendors command
    top_parser = subparsers.add_parser('top-vendors', help='Show top vendors by CVE count')
    top_parser.add_argument('--limit', type=int, default=10, help='Limit results')
    
    # Search command
    search_parser = subparsers.add_parser('search', help='Full-text search')
    search_parser.add_argument('query', help='Search query')
    search_parser.add_argument('--limit', type=int, default=20, help='Limit results')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        query_tool = CVEQueryTool(args.db_path)
        
        if args.command == 'stats':
            stats = query_tool.get_stats()
            print("\n=== CVE Database Statistics ===")
            print(f"Database: {args.db_path}")
            print(f"Total CVEs: {stats['total_cves']:,}")
            print(f"Known Exploited: {stats['known_exploited']:,}")
            print(f"Year Range: {stats['year_range']}")
            print(f"Database Size: {stats['db_size_mb']} MB")
            
        elif args.command == 'cve':
            result = query_tool.search_cve(args.cve_id)
            if result:
                print(f"\n=== CVE Details: {args.cve_id} ===")
                print(f"Year: {result['year']}")
                print(f"Published: {result['published_date']}")
                print(f"State: {result['state']}")
                print(f"Vendors: {result['vendors'] or 'N/A'}")
                print(f"Products: {result['products'] or 'N/A'}")
                print(f"Known Exploited: {'YES' if result['is_known_exploited'] else 'NO'}")
                if result['is_known_exploited']:
                    print(f"KEV Date Added: {result['kev_date_added']}")
                print(f"References: {result['reference_count']}")
                print(f"\nDescription:")
                print(f"  {result['descriptions'] or 'N/A'}")
                if result['problem_types']:
                    print(f"\nProblem Types:")
                    print(f"  {result['problem_types']}")
            else:
                print(f"CVE {args.cve_id} not found in database.")
        
        elif args.command == 'vendor':
            results = query_tool.search_by_vendor(args.vendor_name, args.limit)
            print(f"\n=== CVEs for vendor: {args.vendor_name} ===")
            print_table(results, ['cve_id', 'year', 'vendor', 'product', 'exploited'])
        
        elif args.command == 'product':
            results = query_tool.search_by_product(args.product_name, args.limit)
            print(f"\n=== CVEs for product: {args.product_name} ===")
            print_table(results, ['cve_id', 'year', 'vendor', 'product', 'exploited'])
        
        elif args.command == 'kev':
            results = query_tool.get_known_exploited(args.limit)
            print(f"\n=== Known Exploited Vulnerabilities ===")
            print_table(results, ['cve_id', 'vendor_project', 'product', 'date_added'])
        
        elif args.command == 'years':
            results = query_tool.get_year_stats(args.years)
            print(f"\n=== CVE Statistics by Year ===")
            print_table(results, ['year', 'total_cves', 'known_exploited', 'exploit_rate'])
        
        elif args.command == 'top-vendors':
            results = query_tool.get_top_vendors(args.limit)
            print(f"\n=== Top Vendors by CVE Count ===")
            print_table(results, ['vendor', 'cve_count', 'exploited_count', 'exploit_rate'])
        
        elif args.command == 'search':
            results = query_tool.full_text_search(args.query, args.limit)
            print(f"\n=== Search Results for: {args.query} ===")
            print_table(results, ['cve_id', 'year', 'vendor', 'product', 'exploited'])
        
        query_tool.close()
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main()) 