"""Data models and representations for SheXzTool."""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional
import json


class Severity(str, Enum):
    """Vulnerability and finding severity classifications."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @classmethod
    def from_string(cls, val: str) -> Severity:
        """Parse string to Severity safely."""
        try:
            return cls[val.upper()]
        except KeyError:
            return cls.INFO


@dataclass
class Finding:
    """Represents an individual audit finding, configuration risk, or observation."""
    id: str
    title: str
    category: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to standard dictionary."""
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ScanResult:
    """Comprehensive container for scan outcomes, telemetry, and findings."""
    scan_type: str
    timestamp: str
    system_info: Dict[str, Any]
    findings: List[Finding] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Calculate distribution of findings by severity."""
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def to_dict(self) -> Dict[str, Any]:
        """Serialize full scan results to a dictionary."""
        return {
            "scan_type": self.scan_type,
            "timestamp": self.timestamp,
            "system_info": self.system_info,
            "severity_counts": self.severity_counts,
            "findings": [f.to_dict() for f in self.findings],
            "metrics": self.metrics,
            "limitations": self.limitations,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert scan results to formatted JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)


@dataclass
class ProcessDetail:
    """Detailed metadata for an inspected process."""
    pid: int
    name: str
    exe: Optional[str]
    username: Optional[str]
    cpu_percent: float
    memory_mb: float
    status: str
    is_suspicious: bool = False
    anomaly_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConnectionDetail:
    """Network connection record."""
    laddr: str
    raddr: str
    status: str
    pid: Optional[int]
    process_name: Optional[str]
    protocol: str = "TCP"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BaselineRecord:
    """Baseline entry for a file in File Integrity Monitoring."""
    path: str
    sha256: str
    size_bytes: int
    mtime: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FimComparisonResult:
    """Results of comparing a live directory state against a recorded baseline."""
    root_path: str
    baseline_timestamp: str
    scan_timestamp: str
    new_files: List[str] = field(default_factory=list)
    modified_files: List[Dict[str, str]] = field(default_factory=list)  # path, old_hash, new_hash
    missing_files: List[str] = field(default_factory=list)
    unchanged_count: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_files or self.modified_files or self.missing_files)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
