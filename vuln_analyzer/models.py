"""Data models for vulnerability analysis."""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple


@dataclass
class ComponentAnalysisResult:
    """Result of analyzing a single component (e.g., vendor, product, package name)."""
    
    component_name: str
    component_type: str  # 'vendor', 'product', 'package_name', 'namespace', etc.
    component_value: str
    matched_cves: List[str]
    vulnerability_activity_rate: float
    exploitation_risk: float
    relative_threat_level: float
    risk_summary: Dict[str, Any]
    
    def get_risk_level(self) -> str:
        """Get overall risk level for this component."""
        if self.exploitation_risk >= 0.20:
            return "CRITICAL"
        elif self.exploitation_risk >= 0.10:
            return "HIGH"
        elif self.exploitation_risk >= 0.05:
            return "MEDIUM"
        elif self.exploitation_risk >= 0.01:
            return "LOW"
        else:
            return "VERY_LOW"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "component_name": self.component_name,
            "component_type": self.component_type,
            "component_value": self.component_value,
            "matched_cves": self.matched_cves,
            "vulnerability_activity_rate": self.vulnerability_activity_rate,
            "exploitation_risk": self.exploitation_risk,
            "relative_threat_level": self.relative_threat_level,
            "risk_level": self.get_risk_level(),
            "risk_summary": self.risk_summary
        }


@dataclass
class ComprehensiveAnalysisResult:
    """Result of comprehensive component analysis for PURL or CPE."""
    
    identifier: str
    input_type: str
    overall_analysis: 'AnalysisResult'
    component_analyses: List[ComponentAnalysisResult]
    aggregated_metrics: Dict[str, Any]
    recommendations: List[str]
    
    def get_highest_risk_component(self) -> Optional[ComponentAnalysisResult]:
        """Get the component with the highest exploitation risk."""
        if not self.component_analyses:
            return None
        return max(self.component_analyses, key=lambda x: x.exploitation_risk)
    
    def get_most_active_component(self) -> Optional[ComponentAnalysisResult]:
        """Get the component with the highest vulnerability activity rate."""
        if not self.component_analyses:
            return None
        return max(self.component_analyses, key=lambda x: x.vulnerability_activity_rate)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "identifier": self.identifier,
            "input_type": self.input_type,
            "overall_analysis": self.overall_analysis.to_dict(),
            "component_analyses": [comp.to_dict() for comp in self.component_analyses],
            "aggregated_metrics": self.aggregated_metrics,
            "recommendations": self.recommendations,
            "highest_risk_component": self.get_highest_risk_component().to_dict() if self.get_highest_risk_component() else None,
            "most_active_component": self.get_most_active_component().to_dict() if self.get_most_active_component() else None
        }


@dataclass
class AnalysisResult:
    """Result of vulnerability analysis."""
    
    identifier: str
    input_type: str
    matched_cves: List[str]
    introduction_rate: float  # Legacy: vulnerability_activity_rate for backward compatibility
    history_usage_rate: float  # Legacy: exploitation_risk for backward compatibility
    analysis_period: str
    total_cves_analyzed: int
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    # New enhanced metrics
    vulnerability_activity_rate: Optional[float] = None
    exploitation_risk: Optional[float] = None
    relative_threat_level: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "identifier": self.identifier,
            "input_type": self.input_type,
            "matched_cves": self.matched_cves,
            "introduction_rate": self.introduction_rate,
            "history_usage_rate": self.history_usage_rate,
            "analysis_period": self.analysis_period,
            "total_cves_analyzed": self.total_cves_analyzed,
            "error_message": self.error_message,
            "metadata": self.metadata or {}
        }
        
        # Add enhanced metrics if available
        if self.vulnerability_activity_rate is not None:
            result["vulnerability_activity_rate"] = self.vulnerability_activity_rate
            result["vulnerability_activity_interpretation"] = self._interpret_activity_rate()
        
        if self.exploitation_risk is not None:
            result["exploitation_risk"] = self.exploitation_risk
            result["exploitation_risk_interpretation"] = self._interpret_exploitation_risk()
        
        if self.relative_threat_level is not None:
            result["relative_threat_level"] = self.relative_threat_level
            result["relative_threat_interpretation"] = self._interpret_threat_level()
        
        return result
    
    def _interpret_activity_rate(self) -> str:
        """Interpret vulnerability activity rate."""
        if self.vulnerability_activity_rate is None:
            return "N/A"
        
        rate = self.vulnerability_activity_rate
        if rate >= 3.0:
            return "Very High - Much more active recently than historically"
        elif rate >= 1.5:
            return "High - More active recently than historically"
        elif rate >= 0.8:
            return "Moderate - Similar activity to historical patterns"
        elif rate >= 0.3:
            return "Low - Less active recently than historically"
        else:
            return "Very Low - Much less active recently"
    
    def _interpret_exploitation_risk(self) -> str:
        """Interpret exploitation risk."""
        if self.exploitation_risk is None:
            return "N/A"
        
        risk = self.exploitation_risk
        if risk >= 0.20:
            return "Critical - Over 20% of vulnerabilities are exploited"
        elif risk >= 0.10:
            return "High - 10-20% of vulnerabilities are exploited"
        elif risk >= 0.05:
            return "Medium - 5-10% of vulnerabilities are exploited"
        elif risk >= 0.01:
            return "Low - 1-5% of vulnerabilities are exploited"
        else:
            return "Very Low - Less than 1% of vulnerabilities are exploited"
    
    def _interpret_threat_level(self) -> str:
        """Interpret relative threat level."""
        if self.relative_threat_level is None:
            return "N/A"
        
        level = self.relative_threat_level
        if level >= 0.05:
            return "Critical - Represents >5% of all known exploited vulnerabilities"
        elif level >= 0.02:
            return "High - Represents 2-5% of known exploited vulnerabilities"
        elif level >= 0.01:
            return "Medium - Represents 1-2% of known exploited vulnerabilities"
        elif level >= 0.002:
            return "Low - Represents 0.2-1% of known exploited vulnerabilities"
        else:
            return "Very Low - Minor component in threat landscape"


@dataclass
class CategoryAnalysisResult:
    """Result of analyzing a specific category (e.g., vendors, products, descriptions)."""
    
    category_name: str  # 'vendors', 'products', 'descriptions', 'problem_types'
    category_type: str  # 'vendor', 'product', 'description', 'problem_type'
    matches: Dict[str, List[str]]  # match_value -> list of CVE IDs
    total_cves: int
    unique_matches: int
    vulnerability_activity_rate: float
    exploitation_risk: float
    relative_threat_level: float
    top_matches: List[Tuple[str, int]]  # (match_value, cve_count) sorted by count
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "category_name": self.category_name,
            "category_type": self.category_type,
            "total_cves": self.total_cves,
            "unique_matches": self.unique_matches,
            "vulnerability_activity_rate": self.vulnerability_activity_rate,
            "exploitation_risk": self.exploitation_risk,
            "relative_threat_level": self.relative_threat_level,
            "top_matches": [{"value": match, "cve_count": count} for match, count in self.top_matches[:10]],
            "sample_cves": list(set(sum(self.matches.values(), [])))[:20]  # Sample of all CVEs
        }


@dataclass
class WildcardAnalysisResult:
    """Result of comprehensive wildcard analysis (e.g., 'python *')."""
    
    search_term: str
    input_type: str  # 'wildcard' 
    total_matched_cves: List[str]
    category_analyses: List[CategoryAnalysisResult]
    overall_metrics: Dict[str, Any]
    temporal_analysis: Dict[str, Any]  # CVEs by year, trends
    recommendations: List[str]
    error_message: Optional[str] = None
    
    def get_highest_risk_category(self) -> Optional[CategoryAnalysisResult]:
        """Get the category with the highest exploitation risk."""
        if not self.category_analyses:
            return None
        return max(self.category_analyses, key=lambda x: x.exploitation_risk)
    
    def get_most_active_category(self) -> Optional[CategoryAnalysisResult]:
        """Get the category with the highest vulnerability activity."""
        if not self.category_analyses:
            return None
        return max(self.category_analyses, key=lambda x: x.vulnerability_activity_rate)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "search_term": self.search_term,
            "input_type": self.input_type,
            "total_matched_cves": len(self.total_matched_cves),
            "matched_cves_sample": self.total_matched_cves[:50],  # Show first 50
            "category_analyses": [cat.to_dict() for cat in self.category_analyses],
            "overall_metrics": self.overall_metrics,
            "temporal_analysis": self.temporal_analysis,
            "recommendations": self.recommendations,
            "error_message": self.error_message,
            "highest_risk_category": self.get_highest_risk_category().to_dict() if self.get_highest_risk_category() else None,
            "most_active_category": self.get_most_active_category().to_dict() if self.get_most_active_category() else None
        }


@dataclass
class CVERecord:
    """Represents a CVE record."""
    
    cve_id: str
    published_date: datetime
    updated_date: Optional[datetime]
    vendor: str
    product: str
    versions: List[str]
    description: str
    problem_types: List[str]
    references: List[str]
    severity: Optional[str] = None
    
    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'CVERecord':
        """Create CVERecord from JSON data."""
        try:
            # Extract basic metadata
            cve_id = data.get("cveMetadata", {}).get("cveId", "")
            
            # Handle date parsing with fallback for empty strings
            published_date_str = data.get("cveMetadata", {}).get("datePublished", "")
            if published_date_str:
                try:
                    published_date = datetime.fromisoformat(published_date_str.replace("Z", "+00:00"))
                except ValueError:
                    # Fallback to a default date if parsing fails
                    published_date = datetime(2000, 1, 1)
            else:
                published_date = datetime(2000, 1, 1)
            
            updated_date_str = data.get("cveMetadata", {}).get("dateUpdated")
            updated_date = None
            if updated_date_str:
                try:
                    updated_date = datetime.fromisoformat(updated_date_str.replace("Z", "+00:00"))
                except ValueError:
                    updated_date = None
            
            # Extract affected products
            affected = data.get("containers", {}).get("cna", {}).get("affected", [])
            vendor = "n/a"
            product = "n/a"
            versions = []
            
            if affected:
                vendor = affected[0].get("vendor", "n/a")
                product = affected[0].get("product", "n/a")
                versions = [v.get("version", "") for v in affected[0].get("versions", [])]
            
            # Extract description
            descriptions = data.get("containers", {}).get("cna", {}).get("descriptions", [])
            description = descriptions[0].get("value", "") if descriptions else ""
            
            # Extract problem types
            problem_types_data = data.get("containers", {}).get("cna", {}).get("problemTypes", [])
            problem_types = []
            for pt in problem_types_data:
                for desc in pt.get("descriptions", []):
                    problem_types.append(desc.get("description", ""))
            
            # Extract references
            references_data = data.get("containers", {}).get("cna", {}).get("references", [])
            references = [ref.get("url", "") for ref in references_data]
            
            return cls(
                cve_id=cve_id,
                published_date=published_date,
                updated_date=updated_date,
                vendor=vendor,
                product=product,
                versions=versions,
                description=description,
                problem_types=problem_types,
                references=references
            )
        except Exception as e:
            raise ValueError(f"Error parsing CVE record: {str(e)}")


@dataclass
class MetricsData:
    """Vulnerability metrics calculation data with enhanced calculations."""
    
    total_cves: int  # Total CVEs in entire database
    matched_cves: int  # Total CVEs matching the identifier
    recent_matched_cves: int  # CVEs matching identifier in 2020-2025
    historical_matched_cves: int  # CVEs matching identifier before 2020
    kev_matches: int  # Number of matches in known exploited vulnerabilities
    total_kev_entries: int  # Total KEV entries in database
    
    def calculate_vulnerability_activity_rate(self) -> float:
        """
        Calculate how active this component is in terms of recent vulnerabilities.
        Higher values indicate more active vulnerability discovery/disclosure.
        
        Formula: (Recent CVEs per year) / (Historical CVEs per year)
        
        Returns:
            float: Activity rate where >1.0 means more active recently, <1.0 means less active
        """
        if self.historical_matched_cves == 0:
            # If no historical data, return recent activity rate scaled
            return min(self.recent_matched_cves / 5.0, 10.0)  # Cap at 10x for readability
        
        recent_rate = self.recent_matched_cves / 5.0  # CVEs per year (2020-2025)
        historical_rate = self.historical_matched_cves / 20.0  # CVEs per year (2000-2019)
        
        if historical_rate == 0:
            return min(recent_rate * 10, 10.0)  # Boost if no historical but has recent
        
        return min(recent_rate / historical_rate, 10.0)  # Cap ratio at 10x
    
    def calculate_exploitation_risk(self) -> float:
        """
        Calculate the exploitation risk for this component.
        This tells you what percentage of this component's CVEs have been exploited.
        
        Formula: (KEV matches for component) / (Total CVEs for component)
        
        Returns:
            float: Risk percentage (0.0 to 1.0) where higher values mean more CVEs are exploited
        """
        if self.matched_cves == 0:
            return 0.0
        return self.kev_matches / self.matched_cves
    
    def calculate_relative_threat_level(self) -> float:
        """
        Calculate how this component compares to the overall threat landscape.
        Higher values mean this component represents a larger portion of known threats.
        
        Formula: (KEV matches for component) / (Total KEV entries)
        
        Returns:
            float: Relative threat level (0.0 to 1.0) indicating component's share of total threats
        """
        if self.total_kev_entries == 0:
            return 0.0
        return self.kev_matches / self.total_kev_entries
    
    # Legacy methods for backward compatibility
    def calculate_introduction_rate(self) -> float:
        """
        Legacy method for backward compatibility.
        Returns vulnerability activity rate with the old calculation as fallback.
        """
        # Use new calculation if we have the data
        if hasattr(self, 'historical_matched_cves') and self.historical_matched_cves >= 0:
            return self.calculate_vulnerability_activity_rate()
        
        # Fallback to old calculation
        if self.matched_cves == 0:
            return 0.0
        return self.recent_matched_cves / self.matched_cves
    
    def calculate_usage_rate(self) -> float:
        """
        Legacy method for backward compatibility.
        Returns exploitation risk instead of the old calculation.
        """
        return self.calculate_exploitation_risk()
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """Get a comprehensive risk summary."""
        return {
            "vulnerability_activity": {
                "rate": self.calculate_vulnerability_activity_rate(),
                "recent_cves": self.recent_matched_cves,
                "historical_cves": self.historical_matched_cves,
                "interpretation": self._interpret_activity_rate()
            },
            "exploitation_risk": {
                "rate": self.calculate_exploitation_risk(),
                "exploited_cves": self.kev_matches,
                "total_cves": self.matched_cves,
                "interpretation": self._interpret_exploitation_risk()
            },
            "threat_level": {
                "rate": self.calculate_relative_threat_level(),
                "component_threats": self.kev_matches,
                "total_threats": self.total_kev_entries,
                "interpretation": self._interpret_threat_level()
            }
        }
    
    def _interpret_activity_rate(self) -> str:
        """Interpret vulnerability activity rate."""
        rate = self.calculate_vulnerability_activity_rate()
        if rate >= 3.0:
            return "Very High - Much more active recently than historically"
        elif rate >= 1.5:
            return "High - More active recently than historically"
        elif rate >= 0.8:
            return "Moderate - Similar activity to historical patterns"
        elif rate >= 0.3:
            return "Low - Less active recently than historically"
        else:
            return "Very Low - Much less active recently"
    
    def _interpret_exploitation_risk(self) -> str:
        """Interpret exploitation risk."""
        risk = self.calculate_exploitation_risk()
        if risk >= 0.20:
            return "Critical - Over 20% of vulnerabilities are exploited"
        elif risk >= 0.10:
            return "High - 10-20% of vulnerabilities are exploited"
        elif risk >= 0.05:
            return "Medium - 5-10% of vulnerabilities are exploited"
        elif risk >= 0.01:
            return "Low - 1-5% of vulnerabilities are exploited"
        else:
            return "Very Low - Less than 1% of vulnerabilities are exploited"
    
    def _interpret_threat_level(self) -> str:
        """Interpret relative threat level."""
        level = self.calculate_relative_threat_level()
        if level >= 0.05:
            return "Critical - Represents >5% of all known exploited vulnerabilities"
        elif level >= 0.02:
            return "High - Represents 2-5% of known exploited vulnerabilities"
        elif level >= 0.01:
            return "Medium - Represents 1-2% of known exploited vulnerabilities"
        elif level >= 0.002:
            return "Low - Represents 0.2-1% of known exploited vulnerabilities"
        else:
            return "Very Low - Minor component in threat landscape" 