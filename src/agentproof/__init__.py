"""AgentProof: static security and engineering quality checks for AI agent repos."""

from .models import Finding, ScanResult, Severity
from .scanner import ScanOptions, scan

__all__ = ["Finding", "ScanOptions", "ScanResult", "Severity", "scan"]
__version__ = "0.1.0"
