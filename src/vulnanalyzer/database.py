"""Database interface for vulnerability analysis."""

import json
import re
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from .models import AnalysisResult, CVERecord, MetricsData, WildcardAnalysisResult, CategoryAnalysisResult


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
        """Analyze a CVE using enhanced database queries."""
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
        
        # Count recent and historical CVEs
        recent_cves = []
        historical_cves = []
        
        for matched_cve_id in matched_cves:
            year_match = re.search(r'CVE-(\d{4})-', matched_cve_id)
            if year_match:
                year = int(year_match.group(1))
                if 2020 <= year <= 2025:
                    recent_cves.append(matched_cve_id)
                elif year < 2020:
                    historical_cves.append(matched_cve_id)
        
        # Count KEV matches for all matched CVEs
        kev_matches = 0
        for matched_cve_id in matched_cves:
            cursor = self.conn.execute(
                "SELECT COUNT(*) FROM known_exploited_vulns WHERE cve_id = ?", 
                (matched_cve_id,)
            )
            if cursor.fetchone()[0] > 0:
                kev_matches += 1
        
        # Get total CVEs and KEV entries in database
        cursor = self.conn.execute("SELECT COUNT(*) FROM cve_records")
        total_cves_in_db = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM known_exploited_vulns")
        total_kev_entries = cursor.fetchone()[0]
        
        # Calculate enhanced metrics
        metrics = MetricsData(
            total_cves=total_cves_in_db,
            matched_cves=len(matched_cves),
            recent_matched_cves=len(recent_cves),
            historical_matched_cves=len(historical_cves),
            kev_matches=kev_matches,
            total_kev_entries=total_kev_entries
        )
        
        # Create enhanced analysis result
        result = AnalysisResult(
            identifier=cve_id,
            input_type="cve",
            matched_cves=matched_cves[:50],  # Limit for performance
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"Year {cve_record['year']}",
            total_cves_analyzed=metrics.total_cves,
            vulnerability_activity_rate=metrics.calculate_vulnerability_activity_rate(),
            exploitation_risk=metrics.calculate_exploitation_risk(),
            relative_threat_level=metrics.calculate_relative_threat_level(),
            metadata={
                "vendor": vendors[0] if vendors else "n/a",
                "product": products[0] if products else "n/a",
                "published_date": cve_record['published_date'],
                "is_known_exploited": bool(cve_record['is_known_exploited']),
                "problem_types": cve_record['problem_types'].split(',') if cve_record['problem_types'] else [],
                "risk_summary": metrics.get_risk_summary()
            }
        )
        
        return result
    
    def analyze_package_database(self, package_name: str, package_type: str = None) -> AnalysisResult:
        """Analyze a package using enhanced database queries."""
        # Search for CVEs related to the package
        search_results = self.search_cves_full_text(package_name, limit=200)
        
        matched_cves = [r['cve_id'] for r in search_results]
        
        # Count recent and historical CVEs
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
        
        # Count KEV matches
        kev_matches = len([r for r in search_results if r['is_known_exploited']])
        
        # Get total CVE count and KEV entries for rate calculation
        cursor = self.conn.execute("SELECT COUNT(*) FROM cve_records")
        total_cves = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM known_exploited_vulns")
        total_kev_entries = cursor.fetchone()[0]
        
        # Calculate enhanced metrics
        metrics = MetricsData(
            total_cves=total_cves,
            matched_cves=len(matched_cves),
            recent_matched_cves=len(recent_cves),
            historical_matched_cves=len(historical_cves),
            kev_matches=kev_matches,
            total_kev_entries=total_kev_entries
        )
        
        # Create enhanced analysis result
        result = AnalysisResult(
            identifier=package_name,
            input_type="purl" if package_type else "package",
            matched_cves=matched_cves[:100],  # Limit for performance
            introduction_rate=metrics.calculate_introduction_rate(),
            history_usage_rate=metrics.calculate_usage_rate(),
            analysis_period=f"All years (focused on {package_name})",
            total_cves_analyzed=len(matched_cves),
            vulnerability_activity_rate=metrics.calculate_vulnerability_activity_rate(),
            exploitation_risk=metrics.calculate_exploitation_risk(),
            relative_threat_level=metrics.calculate_relative_threat_level(),
            metadata={
                "package_name": package_name,
                "package_type": package_type,
                "search_results": len(search_results),
                "risk_summary": metrics.get_risk_summary()
            }
        )
        
        return result
    
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
    
    def get_enhanced_vulnerability_analysis(self, identifier: str, identifier_type: str) -> Dict[str, Any]:
        """Get comprehensive vulnerability analysis with risk assessment."""
        if identifier_type.lower() == "cve":
            result = self.analyze_cve_database(identifier)
        else:
            result = self.analyze_package_database(identifier, identifier_type)
        
        # Add additional risk context
        analysis = result.to_dict()
        
        # Add risk recommendations
        if result.exploitation_risk is not None:
            if result.exploitation_risk >= 0.20:
                analysis["risk_recommendation"] = "CRITICAL - Immediate attention required"
            elif result.exploitation_risk >= 0.10:
                analysis["risk_recommendation"] = "HIGH - Priority patching needed"
            elif result.exploitation_risk >= 0.05:
                analysis["risk_recommendation"] = "MEDIUM - Monitor and plan patching"
            else:
                analysis["risk_recommendation"] = "LOW - Normal patching cycle"
        
        # Add activity trend interpretation
        if result.vulnerability_activity_rate is not None:
            if result.vulnerability_activity_rate >= 2.0:
                analysis["activity_trend"] = "Component is experiencing increased vulnerability discovery"
            elif result.vulnerability_activity_rate <= 0.5:
                analysis["activity_trend"] = "Component has lower recent vulnerability activity"
            else:
                analysis["activity_trend"] = "Component has normal vulnerability discovery patterns"
        
        return analysis 

    def analyze_wildcard_database(self, search_term: str) -> WildcardAnalysisResult:
        """Perform comprehensive wildcard analysis using database queries."""
        if not self.conn:
            raise RuntimeError("Database not connected")
        
        try:
            # Clean up search term
            search_term = search_term.strip()
            if search_term.endswith(' *'):
                search_term = search_term[:-2].strip()
            
            category_analyses = []
            all_matched_cves = set()
            
            # Search in vendors
            vendor_analysis = self._analyze_category_database_search(search_term, "vendors", "vendor")
            if vendor_analysis:
                category_analyses.append(vendor_analysis)
                all_matched_cves.update(sum(vendor_analysis.matches.values(), []))
            
            # Search in products
            product_analysis = self._analyze_category_database_search(search_term, "products", "product")
            if product_analysis:
                category_analyses.append(product_analysis)
                all_matched_cves.update(sum(product_analysis.matches.values(), []))
            
            # Search in descriptions
            description_analysis = self._analyze_category_database_search(search_term, "descriptions", "description")
            if description_analysis:
                category_analyses.append(description_analysis)
                all_matched_cves.update(sum(description_analysis.matches.values(), []))
            
            # Search in problem types
            problem_type_analysis = self._analyze_category_database_search(search_term, "problem_types", "problem_type")
            if problem_type_analysis:
                category_analyses.append(problem_type_analysis)
                all_matched_cves.update(sum(problem_type_analysis.matches.values(), []))
            
            all_matched_cves = list(all_matched_cves)
            
            # Calculate overall metrics
            overall_metrics = self._calculate_wildcard_database_metrics(all_matched_cves)
            
            # Temporal analysis
            temporal_analysis = self._calculate_temporal_database_analysis(all_matched_cves)
            
            # Generate recommendations
            recommendations = self._generate_wildcard_database_recommendations(search_term, category_analyses, overall_metrics)
            
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
    
    def _analyze_category_database_search(self, search_term: str, category_name: str, category_type: str) -> Optional[CategoryAnalysisResult]:
        """Search for a term within a specific category using database queries."""
        if not self.conn:
            return None
        
        matches = {}  # match_value -> list of CVE IDs
        
        try:
            if category_type == "vendor":
                cursor = self.conn.execute("""
                    SELECT DISTINCT c.cve_id, a.vendor
                    FROM cve_records c
                    JOIN cve_affected a ON c.cve_id = a.cve_id
                    WHERE a.vendor LIKE ? AND a.vendor NOT IN ('n/a', '') AND a.vendor IS NOT NULL
                    ORDER BY c.published_date DESC
                    LIMIT 5000
                """, (f"%{search_term}%",))
                
                for row in cursor.fetchall():
                    vendor = row['vendor']
                    if vendor not in matches:
                        matches[vendor] = []
                    matches[vendor].append(row['cve_id'])
            
            elif category_type == "product":
                cursor = self.conn.execute("""
                    SELECT DISTINCT c.cve_id, a.product
                    FROM cve_records c
                    JOIN cve_affected a ON c.cve_id = a.cve_id
                    WHERE a.product LIKE ? AND a.product NOT IN ('n/a', '') AND a.product IS NOT NULL
                    ORDER BY c.published_date DESC
                    LIMIT 5000
                """, (f"%{search_term}%",))
                
                for row in cursor.fetchall():
                    product = row['product']
                    if product not in matches:
                        matches[product] = []
                    matches[product].append(row['cve_id'])
            
            elif category_type == "description":
                cursor = self.conn.execute("""
                    SELECT DISTINCT c.cve_id, d.value
                    FROM cve_records c
                    JOIN cve_descriptions d ON c.cve_id = d.cve_id
                    WHERE d.value LIKE ? AND d.lang = 'en'
                    ORDER BY c.published_date DESC
                    LIMIT 5000
                """, (f"%{search_term}%",))
                
                for row in cursor.fetchall():
                    # Create a snippet of the description
                    description = row['value']
                    desc_words = description.lower().split()
                    term_index = next((i for i, word in enumerate(desc_words) if search_term.lower() in word), None)
                    if term_index is not None:
                        start = max(0, term_index - 3)
                        end = min(len(desc_words), term_index + 4)
                        snippet = ' '.join(desc_words[start:end])
                        if snippet not in matches:
                            matches[snippet] = []
                        matches[snippet].append(row['cve_id'])
            
            elif category_type == "problem_type":
                cursor = self.conn.execute("""
                    SELECT DISTINCT c.cve_id, pt.description
                    FROM cve_records c
                    JOIN cve_problem_types pt ON c.cve_id = pt.cve_id
                    WHERE pt.description LIKE ?
                    ORDER BY c.published_date DESC
                    LIMIT 5000
                """, (f"%{search_term}%",))
                
                for row in cursor.fetchall():
                    problem_type = row['description']
                    if problem_type not in matches:
                        matches[problem_type] = []
                    matches[problem_type].append(row['cve_id'])
            
            if not matches:
                return None
            
            # Calculate metrics for this category
            all_category_cves = sum(matches.values(), [])
            unique_cves = list(set(all_category_cves))
            metrics = self._calculate_category_database_metrics(unique_cves)
            
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
            
        except Exception as e:
            print(f"Error in category search for {category_type}: {e}")
            return None
    
    def _calculate_category_database_metrics(self, unique_cves: List[str]) -> MetricsData:
        """Calculate metrics for a category using database queries."""
        if not self.conn or not unique_cves:
            return MetricsData(0, 0, 0, 0, 0, 0)
        
        # Count recent vs historical
        recent_cves = []
        historical_cves = []
        
        for cve_id in unique_cves:
            year_match = re.search(r'CVE-(\d{4})-', cve_id)
            if year_match:
                year = int(year_match.group(1))
                if 2020 <= year <= 2025:
                    recent_cves.append(cve_id)
                elif year < 2020:
                    historical_cves.append(cve_id)
        
        # Count KEV matches
        if unique_cves:
            placeholders = ','.join(['?' for _ in unique_cves])
            cursor = self.conn.execute(f"""
                SELECT COUNT(*) FROM known_exploited_vulns 
                WHERE cve_id IN ({placeholders})
            """, unique_cves)
            kev_matches = cursor.fetchone()[0]
        else:
            kev_matches = 0
        
        # Get total CVEs and KEV entries
        cursor = self.conn.execute("SELECT COUNT(*) FROM cve_records")
        total_cves = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM known_exploited_vulns")
        total_kev_entries = cursor.fetchone()[0]
        
        return MetricsData(
            total_cves=total_cves,
            matched_cves=len(unique_cves),
            recent_matched_cves=len(recent_cves),
            historical_matched_cves=len(historical_cves),
            kev_matches=kev_matches,
            total_kev_entries=total_kev_entries
        )
    
    def _calculate_wildcard_database_metrics(self, all_matched_cves: List[str]) -> Dict[str, Any]:
        """Calculate overall metrics for wildcard analysis using database."""
        if not self.conn or not all_matched_cves:
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
        
        # Count KEV matches
        if all_matched_cves:
            placeholders = ','.join(['?' for _ in all_matched_cves])
            cursor = self.conn.execute(f"""
                SELECT COUNT(*) FROM known_exploited_vulns 
                WHERE cve_id IN ({placeholders})
            """, all_matched_cves)
            kev_matches = cursor.fetchone()[0]
        else:
            kev_matches = 0
        
        # Get total CVEs and KEV entries
        cursor = self.conn.execute("SELECT COUNT(*) FROM cve_records")
        total_cves = cursor.fetchone()[0]
        
        cursor = self.conn.execute("SELECT COUNT(*) FROM known_exploited_vulns")
        total_kev_entries = cursor.fetchone()[0]
        
        # Calculate metrics
        metrics = MetricsData(
            total_cves=total_cves,
            matched_cves=len(all_matched_cves),
            recent_matched_cves=len(recent_cves),
            historical_matched_cves=len(historical_cves),
            kev_matches=kev_matches,
            total_kev_entries=total_kev_entries
        )
        
        return {
            "total_matched_cves": len(all_matched_cves),
            "recent_cves": len(recent_cves),
            "historical_cves": len(historical_cves),
            "known_exploited_cves": kev_matches,
            "vulnerability_activity_rate": metrics.calculate_vulnerability_activity_rate(),
            "exploitation_risk": metrics.calculate_exploitation_risk(),
            "relative_threat_level": metrics.calculate_relative_threat_level(),
            "database_coverage": len(all_matched_cves) / total_cves if total_cves > 0 else 0.0
        }
    
    def _calculate_temporal_database_analysis(self, all_matched_cves: List[str]) -> Dict[str, Any]:
        """Calculate temporal analysis using database queries."""
        if not self.conn or not all_matched_cves:
            return {}
        
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
    
    def _generate_wildcard_database_recommendations(self, search_term: str, category_analyses: List[CategoryAnalysisResult], overall_metrics: Dict[str, Any]) -> List[str]:
        """Generate recommendations for wildcard analysis using database insights."""
        recommendations = []
        
        if not category_analyses:
            return [f"No vulnerabilities found related to '{search_term}' in database"]
        
        # Overall risk assessment
        total_cves = overall_metrics.get("total_matched_cves", 0)
        exploitation_risk = overall_metrics.get("exploitation_risk", 0.0)
        activity_rate = overall_metrics.get("vulnerability_activity_rate", 0.0)
        coverage = overall_metrics.get("database_coverage", 0.0)
        
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
        
        if coverage >= 0.05:
            recommendations.append(f"LARGE SCOPE: '{search_term}' affects {coverage:.1%} of all vulnerabilities in database - consider ecosystem-wide review")
        elif coverage >= 0.01:
            recommendations.append(f"SIGNIFICANT SCOPE: '{search_term}' affects {coverage:.1%} of database vulnerabilities - systematic review recommended")
        
        # Category-specific recommendations
        high_risk_categories = [cat for cat in category_analyses if cat.exploitation_risk >= 0.10]
        if high_risk_categories:
            recommendations.append(f"High-risk categories found: {', '.join([cat.category_name for cat in high_risk_categories])}")
            
            for cat in high_risk_categories[:3]:  # Top 3 high-risk categories
                top_match = cat.top_matches[0] if cat.top_matches else ("unknown", 0)
                recommendations.append(f"  - {cat.category_name}: '{top_match[0]}' has {top_match[1]} CVEs with {cat.exploitation_risk:.1%} exploitation risk")
        
        return recommendations if recommendations else [f"'{search_term}' shows normal vulnerability patterns in database"] 