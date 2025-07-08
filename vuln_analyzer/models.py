"""Data models for vulnerability analysis."""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any


@dataclass
class AnalysisResult:
    """Result of vulnerability analysis."""
    
    identifier: str
    input_type: str
    matched_cves: List[str]
    introduction_rate: float
    history_usage_rate: float
    analysis_period: str
    total_cves_analyzed: int
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
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
    """Vulnerability metrics calculation data."""
    
    total_cves: int
    matched_cves: int
    time_period_days: int
    introduction_events: int
    usage_events: int
    
    def calculate_introduction_rate(self) -> float:
        """Calculate vulnerability introduction rate."""
        if self.total_cves == 0:
            return 0.0
        return self.matched_cves / self.total_cves
    
    def calculate_usage_rate(self) -> float:
        """Calculate historical usage rate."""
        if self.total_cves == 0:
            return 0.0
        return self.usage_events / self.total_cves 