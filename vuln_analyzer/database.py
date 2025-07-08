"""Database interface for vulnerability analysis."""

import json
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from .models import AnalysisResult, CVERecord, MetricsData


class CVEDatabase:
    """Interface for querying the CVE database."""
    
    def __init__(self, db_path: str):
        """Initialize database connection."""
        self.db_path = Path(db_path)
        self.conn: Optional[sqlite3.Connection] = None
        
        if not self.db_path.exists():
            raise FileNotFoundError(f"Database not found: {db_path}")
    
    def connect(self) -> None:
        """Connect to the database."""
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
    
    def disconnect(self) -> None:
        """Disconnect from the database."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def __enter__(self):
        """Context manager entry."""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.disconnect()
    
    def get_cve_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a CVE record by ID."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        cursor = self.conn.execute("""
            SELECT c.*, 
                   GROUP_CONCAT(d.value, ' | ') as descriptions,
                   GROUP_CONCAT(a.vendor) as vendors,
                   GROUP_CONCAT(a.product) as products,
                   GROUP_CONCAT(pt.description) as problem_types,
                   COUNT(r.url) as reference_count,
                   CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_known_exploited
            FROM cve_records c
            LEFT JOIN cve_descriptions d ON c.cve_id = d.cve_id AND d.lang = 'en'
            LEFT JOIN cve_affected a ON c.cve_id = a.cve_id
            LEFT JOIN cve_problem_types pt ON c.cve_id = pt.cve_id
            LEFT JOIN cve_references r ON c.cve_id = r.cve_id
            LEFT JOIN known_exploited_vulns k ON c.cve_id = k.cve_id
            WHERE c.cve_id = ?
            GROUP BY c.cve_id, c.year, c.published_date, c.updated_date, c.state, 
                     c.assigner_org_id, c.assigner_short_name, c.data_version, c.created_at
        """, (cve_id.upper(),))
        
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def search_cves_by_vendor_product(self, vendor: str = None, product: str = None, 
                                     limit: int = 100) -> List[Dict[str, Any]]:
        """Search CVEs by vendor and/or product."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        conditions = []
        params = []
        
        if vendor:
            conditions.append("a.vendor LIKE ?")
            params.append(f"%{vendor}%")
        
        if product:
            conditions.append("a.product LIKE ?")
            params.append(f"%{product}%")
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        cursor = self.conn.execute(f"""
            SELECT DISTINCT c.cve_id, c.year, c.published_date,
                   a.vendor, a.product,
                   d.value as description,
                   CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_known_exploited
            FROM cve_records c
            LEFT JOIN cve_affected a ON c.cve_id = a.cve_id
            LEFT JOIN cve_descriptions d ON c.cve_id = d.cve_id AND d.lang = 'en'
            LEFT JOIN known_exploited_vulns k ON c.cve_id = k.cve_id
            WHERE {where_clause}
            ORDER BY c.published_date DESC
            LIMIT ?
        """, params + [limit])
        
        return [dict(row) for row in cursor.fetchall()]
    
    def search_cves_full_text(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Full-text search across CVE data."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        cursor = self.conn.execute("""
            SELECT s.cve_id, s.vendor, s.product, s.description,
                   c.year, c.published_date,
                   CASE WHEN k.cve_id IS NOT NULL THEN 1 ELSE 0 END as is_known_exploited,
                   rank
            FROM cve_search s
            JOIN cve_records c ON s.cve_id = c.cve_id
            LEFT JOIN known_exploited_vulns k ON s.cve_id = k.cve_id
            WHERE cve_search MATCH ?
            ORDER BY rank
            LIMIT ?
        """, (query, limit))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_known_exploited_vulns(self, limit: int = None) -> List[Dict[str, Any]]:
        """Get known exploited vulnerabilities."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        query = """
            SELECT k.*, c.year, c.published_date
            FROM known_exploited_vulns k
            LEFT JOIN cve_records c ON k.cve_id = c.cve_id
            ORDER BY k.date_added DESC
        """
        
        params = []
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        
        cursor = self.conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]
    
    def get_vulnerability_trends(self, years: int = 5) -> Dict[str, Any]:
        """Get vulnerability trends over time."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        # CVEs by year
        cursor = self.conn.execute("""
            SELECT year, COUNT(*) as count
            FROM cve_records
            WHERE year >= (SELECT MAX(year) FROM cve_records) - ?
            GROUP BY year
            ORDER BY year
        """, (years,))
        
        years_data = dict(cursor.fetchall())
        
        # Known exploited by year
        cursor = self.conn.execute("""
            SELECT c.year, COUNT(*) as count
            FROM known_exploited_vulns k
            JOIN cve_records c ON k.cve_id = c.cve_id
            WHERE c.year >= (SELECT MAX(year) FROM cve_records) - ?
            GROUP BY c.year
            ORDER BY c.year
        """, (years,))
        
        exploited_data = dict(cursor.fetchall())
        
        # Top vendors
        cursor = self.conn.execute("""
            SELECT a.vendor, COUNT(*) as count
            FROM cve_affected a
            JOIN cve_records c ON a.cve_id = c.cve_id
            WHERE c.year >= (SELECT MAX(year) FROM cve_records) - ? 
                  AND a.vendor NOT IN ('n/a', '') 
                  AND a.vendor IS NOT NULL
            GROUP BY a.vendor
            ORDER BY count DESC
            LIMIT 10
        """, (years,))
        
        top_vendors = dict(cursor.fetchall())
        
        return {
            'years_data': years_data,
            'exploited_data': exploited_data,
            'top_vendors': top_vendors
        }
    
    def analyze_cve_database(self, cve_id: str) -> AnalysisResult:
        """Analyze a CVE using database queries."""
        cve_record = self.get_cve_by_id(cve_id)
        
        if not cve_record:
            return AnalysisResult(
                identifier=cve_id,
                input_type="cve",
                matched_cves=[],
                introduction_rate=0.0,
                history_usage_rate=0.0,
                analysis_period="N/A",
                total_cves_analyzed=0,
                error_message=f"CVE {cve_id} not found in database"
            )
        
        # Find related CVEs
        vendors = cve_record['vendors'].split(',') if cve_record['vendors'] else []
        products = cve_record['products'].split(',') if cve_record['products'] else []
        
        related_cves = []
        for vendor in vendors:
            if vendor and vendor.strip() != 'n/a':
                related = self.search_cves_by_vendor_product(vendor=vendor.strip(), limit=50)
                related_cves.extend([r['cve_id'] for r in related])
        
        for product in products:
            if product and product.strip() != 'n/a':
                related = self.search_cves_by_vendor_product(product=product.strip(), limit=50)
                related_cves.extend([r['cve_id'] for r in related])
        
        # Remove duplicates and ensure original CVE is included
        matched_cves = list(set([cve_id] + related_cves))
        
        # Calculate metrics
        metrics = MetricsData(
            total_cves=len(matched_cves),
            matched_cves=len(matched_cves),
            time_period_days=(datetime.now() - datetime.fromisoformat(
                cve_record['published_date'].replace('Z', '+00:00')
            )).days if cve_record['published_date'] else 0,
            introduction_events=len(related_cves),
            usage_events=cve_record['reference_count'] + (1 if cve_record['is_known_exploited'] else 0)
        )
        
        return AnalysisResult(
            identifier=cve_id,
            input_type="cve",
            matched_cves=matched_cves[:50],  # Limit for performance
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"Year {cve_record['year']}",
            total_cves_analyzed=metrics.total_cves,
            metadata={
                "vendor": vendors[0] if vendors else "n/a",
                "product": products[0] if products else "n/a",
                "published_date": cve_record['published_date'],
                "is_known_exploited": bool(cve_record['is_known_exploited']),
                "problem_types": cve_record['problem_types'].split(',') if cve_record['problem_types'] else []
            }
        )
    
    def analyze_package_database(self, package_name: str, package_type: str = None) -> AnalysisResult:
        """Analyze a package using database queries."""
        # Search for CVEs related to the package
        search_results = self.search_cves_full_text(package_name, limit=200)
        
        matched_cves = [r['cve_id'] for r in search_results]
        
        # Get total CVE count for rate calculation
        cursor = self.conn.execute("SELECT COUNT(*) FROM cve_records")
        total_cves = cursor.fetchone()[0]
        
        # Calculate metrics
        metrics = MetricsData(
            total_cves=total_cves,
            matched_cves=len(matched_cves),
            time_period_days=365 * 5,  # 5 years
            introduction_events=len(matched_cves),
            usage_events=len([r for r in search_results if r['is_known_exploited']])
        )
        
        return AnalysisResult(
            identifier=package_name,
            input_type="purl" if package_type else "package",
            matched_cves=matched_cves[:100],  # Limit for performance
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"All years (focused on {package_name})",
            total_cves_analyzed=len(matched_cves),
            metadata={
                "package_name": package_name,
                "package_type": package_type,
                "search_results": len(search_results)
            }
        )
    
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
        
        return stats 