"""VulnAnalyzer - Professional vulnerability analysis tool for CVE, PURL, CPE, and wildcard searches."""

__version__ = "0.1.0"
__author__ = "Vulnerability Analysis Team"
__description__ = "Professional vulnerability analysis tool for CVE, PURL, CPE, and wildcard searches"
__url__ = "https://github.com/your-org/vulnanalyzer"

from .data_processor import VulnerabilityProcessor
from .database import CVEDatabase
from .database_manager import DatabaseManager
from .models import (
    AnalysisResult,
    ComprehensiveAnalysisResult,
    WildcardAnalysisResult,
    ComponentAnalysisResult,
    CategoryAnalysisResult,
    CVERecord,
    MetricsData
)

__all__ = [
    "VulnerabilityProcessor",
    "CVEDatabase", 
    "DatabaseManager",
    "AnalysisResult",
    "ComprehensiveAnalysisResult",
    "WildcardAnalysisResult",
    "ComponentAnalysisResult",
    "CategoryAnalysisResult",
    "CVERecord",
    "MetricsData"
] 