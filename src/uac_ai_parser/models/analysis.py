"""
Data models for AI analysis results.

These models represent the outputs from AI-powered analysis including
anomaly detection, query results, and incident summaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class AnomalySeverity(str, Enum):
    """Severity levels for detected anomalies."""
    
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AnomalyType(str, Enum):
    """Types of anomalies that can be detected."""
    
    DELETED_BINARY = "deleted_binary"
    SUSPICIOUS_PROCESS = "suspicious_process"
    UNUSUAL_NETWORK = "unusual_network"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    HIDDEN_FILE = "hidden_file"
    SUSPICIOUS_CRON = "suspicious_cron"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    TIMELINE_ANOMALY = "timeline_anomaly"
    HASH_MISMATCH = "hash_mismatch"
    SUSPICIOUS_USER = "suspicious_user"
    CONFIG_MODIFICATION = "config_modification"
    LOG_TAMPERING = "log_tampering"
    ROOTKIT_INDICATOR = "rootkit_indicator"
    UNKNOWN = "unknown"


class Evidence(BaseModel):
    """Evidence supporting an analysis conclusion."""
    
    artifact_type: str = Field(description="Type of artifact (process, file, log, etc.)")
    artifact_path: str | None = Field(default=None, description="Path to the source artifact")
    raw_data: str | None = Field(default=None, description="Raw artifact content snippet")
    parsed_data: dict[str, Any] = Field(default_factory=dict, description="Parsed artifact data")
    relevance_score: float = Field(default=0.5, ge=0, le=1, description="How relevant this evidence is")
    explanation: str | None = Field(default=None, description="Why this evidence is relevant")
    
    def to_markdown(self) -> str:
        """Format evidence as markdown."""
        md = f"**{self.artifact_type}**"
        if self.artifact_path:
            md += f" (`{self.artifact_path}`)"
        md += "\n"
        if self.explanation:
            md += f"- {self.explanation}\n"
        if self.raw_data:
            md += f"```\n{self.raw_data[:500]}{'...' if len(self.raw_data) > 500 else ''}\n```\n"
        return md


class Anomaly(BaseModel):
    """A detected anomaly in the forensic data."""
    
    anomaly_id: str = Field(description="Unique identifier for this anomaly")
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    score: float = Field(ge=0, le=1, description="Confidence score (0-1)")
    
    title: str = Field(description="Short title describing the anomaly")
    description: str = Field(description="Detailed description of the anomaly")
    
    # Source information
    source_artifact: str | None = None
    artifact_path: str | None = None
    
    # Evidence
    evidence: list[Evidence] = Field(default_factory=list)
    
    # Context
    timestamp: datetime | None = None
    hostname: str | None = None
    username: str | None = None
    process_name: str | None = None
    
    # MITRE ATT&CK mapping (future enhancement)
    mitre_technique: str | None = None
    mitre_tactic: str | None = None
    
    # Recommendations
    investigation_steps: list[str] = Field(default_factory=list)
    remediation_steps: list[str] = Field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "anomaly_id": self.anomaly_id,
            "type": self.anomaly_type.value,
            "severity": self.severity.value,
            "score": self.score,
            "title": self.title,
            "description": self.description,
            "source_artifact": self.source_artifact,
            "artifact_path": self.artifact_path,
            "evidence_count": len(self.evidence),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "hostname": self.hostname,
            "username": self.username,
            "process_name": self.process_name,
            "mitre_technique": self.mitre_technique,
            "investigation_steps": self.investigation_steps,
            "remediation_steps": self.remediation_steps,
        }
    
    def to_markdown(self) -> str:
        """Format anomaly as markdown."""
        severity_emoji = {
            AnomalySeverity.CRITICAL: "🔴",
            AnomalySeverity.HIGH: "🟠",
            AnomalySeverity.MEDIUM: "🟡",
            AnomalySeverity.LOW: "🟢",
            AnomalySeverity.INFO: "🔵",
        }
        
        md = f"### {severity_emoji.get(self.severity, '⚪')} {self.title}\n\n"
        md += f"**Severity:** {self.severity.value.upper()} | **Score:** {self.score:.2f} | **Type:** {self.anomaly_type.value}\n\n"
        md += f"{self.description}\n\n"
        
        if self.source_artifact:
            md += f"**Source:** `{self.source_artifact}`\n"
        if self.timestamp:
            md += f"**Timestamp:** {self.timestamp.isoformat()}\n"
        if self.username:
            md += f"**User:** {self.username}\n"
        if self.process_name:
            md += f"**Process:** {self.process_name}\n"
        
        if self.evidence:
            md += "\n#### Evidence\n\n"
            for ev in self.evidence[:5]:  # Limit to 5 evidence items
                md += ev.to_markdown() + "\n"
        
        if self.investigation_steps:
            md += "\n#### Investigation Steps\n\n"
            for i, step in enumerate(self.investigation_steps, 1):
                md += f"{i}. {step}\n"
        
        if self.remediation_steps:
            md += "\n#### Remediation\n\n"
            for i, step in enumerate(self.remediation_steps, 1):
                md += f"{i}. {step}\n"
        
        return md


class AnomalyReport(BaseModel):
    """Complete anomaly detection report."""
    
    report_id: str
    generated_at: datetime
    source_file: str
    hostname: str | None = None
    
    # Anomalies by severity
    anomalies: list[Anomaly] = Field(default_factory=list)
    
    # Summary statistics
    total_artifacts_analyzed: int = 0
    analysis_duration_seconds: float = 0
    
    # Model information
    model_used: str | None = None
    model_version: str | None = None
    
    @property
    def critical_anomalies(self) -> list[Anomaly]:
        """Filter critical severity anomalies."""
        return [a for a in self.anomalies if a.severity == AnomalySeverity.CRITICAL]
    
    @property
    def high_anomalies(self) -> list[Anomaly]:
        """Filter high severity anomalies."""
        return [a for a in self.anomalies if a.severity == AnomalySeverity.HIGH]
    
    @property
    def medium_anomalies(self) -> list[Anomaly]:
        """Filter medium severity anomalies."""
        return [a for a in self.anomalies if a.severity == AnomalySeverity.MEDIUM]
    
    @property
    def anomaly_summary(self) -> dict[str, int]:
        """Get count of anomalies by severity."""
        return {
            "critical": len(self.critical_anomalies),
            "high": len(self.high_anomalies),
            "medium": len(self.medium_anomalies),
            "low": len([a for a in self.anomalies if a.severity == AnomalySeverity.LOW]),
            "info": len([a for a in self.anomalies if a.severity == AnomalySeverity.INFO]),
            "total": len(self.anomalies),
        }
    
    def to_markdown(self) -> str:
        """Generate markdown report."""
        md = f"# Anomaly Detection Report\n\n"
        md += f"**Generated:** {self.generated_at.isoformat()}\n"
        md += f"**Source:** `{self.source_file}`\n"
        if self.hostname:
            md += f"**Hostname:** {self.hostname}\n"
        md += f"**Model:** {self.model_used or 'Unknown'}\n\n"
        
        # Summary
        summary = self.anomaly_summary
        md += "## Summary\n\n"
        md += f"| Severity | Count |\n|----------|-------|\n"
        md += f"| 🔴 Critical | {summary['critical']} |\n"
        md += f"| 🟠 High | {summary['high']} |\n"
        md += f"| 🟡 Medium | {summary['medium']} |\n"
        md += f"| 🟢 Low | {summary['low']} |\n"
        md += f"| 🔵 Info | {summary['info']} |\n"
        md += f"| **Total** | **{summary['total']}** |\n\n"
        
        # Anomalies by severity
        if self.critical_anomalies:
            md += "## 🔴 Critical Anomalies\n\n"
            for anomaly in self.critical_anomalies:
                md += anomaly.to_markdown() + "\n---\n\n"
        
        if self.high_anomalies:
            md += "## 🟠 High Severity Anomalies\n\n"
            for anomaly in self.high_anomalies:
                md += anomaly.to_markdown() + "\n---\n\n"
        
        if self.medium_anomalies:
            md += "## 🟡 Medium Severity Anomalies\n\n"
            for anomaly in self.medium_anomalies:
                md += anomaly.to_markdown() + "\n---\n\n"
        
        return md


class QueryResult(BaseModel):
    """Result from an AI query against the forensic data."""
    
    query: str = Field(description="Original user query")
    answer: str = Field(description="AI-generated answer")
    confidence: float = Field(ge=0, le=1, description="Confidence in the answer")
    
    # Supporting evidence
    evidence: list[Evidence] = Field(default_factory=list)
    
    # Related artifacts
    related_artifacts: list[str] = Field(default_factory=list)
    
    # Query metadata
    query_time_seconds: float = 0
    tokens_used: int | None = None
    model_used: str | None = None
    
    # Follow-up suggestions
    suggested_queries: list[str] = Field(default_factory=list)
    
    def to_markdown(self) -> str:
        """Format result as markdown."""
        md = f"## Query: {self.query}\n\n"
        md += f"**Confidence:** {self.confidence:.2f}\n\n"
        md += f"### Answer\n\n{self.answer}\n\n"
        
        if self.evidence:
            md += "### Supporting Evidence\n\n"
            for ev in self.evidence[:10]:
                md += ev.to_markdown() + "\n"
        
        if self.suggested_queries:
            md += "### Suggested Follow-up Queries\n\n"
            for q in self.suggested_queries:
                md += f"- {q}\n"
        
        return md


@dataclass
class IncidentSummary:
    """AI-generated incident summary."""
    
    title: str
    executive_summary: str
    
    # Timeline
    incident_start: datetime | None = None
    incident_end: datetime | None = None
    key_events: list[dict[str, Any]] = field(default_factory=list)
    
    # Affected resources
    affected_hosts: list[str] = field(default_factory=list)
    affected_users: list[str] = field(default_factory=list)
    affected_services: list[str] = field(default_factory=list)
    
    # IOCs
    iocs: dict[str, list[str]] = field(default_factory=dict)  # type -> values
    
    # Attack chain (if identifiable)
    attack_phases: list[dict[str, str]] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    
    # Recommendations
    immediate_actions: list[str] = field(default_factory=list)
    long_term_recommendations: list[str] = field(default_factory=list)
    
    # Confidence and limitations
    confidence_level: str = "medium"
    analysis_limitations: list[str] = field(default_factory=list)
    
    def to_markdown(self) -> str:
        """Generate markdown incident report."""
        md = f"# Incident Report: {self.title}\n\n"
        
        md += "## Executive Summary\n\n"
        md += f"{self.executive_summary}\n\n"
        
        if self.incident_start or self.incident_end:
            md += "## Timeline\n\n"
            if self.incident_start:
                md += f"**Start:** {self.incident_start.isoformat()}\n"
            if self.incident_end:
                md += f"**End:** {self.incident_end.isoformat()}\n"
            md += "\n"
        
        if self.key_events:
            md += "### Key Events\n\n"
            md += "| Time | Event | Details |\n|------|-------|--------|\n"
            for event in self.key_events:
                md += f"| {event.get('time', 'N/A')} | {event.get('event', '')} | {event.get('details', '')} |\n"
            md += "\n"
        
        if self.affected_hosts or self.affected_users:
            md += "## Impact\n\n"
            if self.affected_hosts:
                md += f"**Affected Hosts:** {', '.join(self.affected_hosts)}\n"
            if self.affected_users:
                md += f"**Affected Users:** {', '.join(self.affected_users)}\n"
            if self.affected_services:
                md += f"**Affected Services:** {', '.join(self.affected_services)}\n"
            md += "\n"
        
        if self.iocs:
            md += "## Indicators of Compromise (IOCs)\n\n"
            for ioc_type, values in self.iocs.items():
                md += f"### {ioc_type}\n"
                for v in values[:20]:  # Limit to 20 per type
                    md += f"- `{v}`\n"
                md += "\n"
        
        if self.attack_phases:
            md += "## Attack Chain\n\n"
            for i, phase in enumerate(self.attack_phases, 1):
                md += f"{i}. **{phase.get('phase', 'Unknown')}**: {phase.get('description', '')}\n"
            md += "\n"
        
        if self.mitre_techniques:
            md += "## MITRE ATT&CK Techniques\n\n"
            for tech in self.mitre_techniques:
                md += f"- {tech}\n"
            md += "\n"
        
        if self.immediate_actions:
            md += "## Immediate Actions Required\n\n"
            for i, action in enumerate(self.immediate_actions, 1):
                md += f"{i}. {action}\n"
            md += "\n"
        
        if self.long_term_recommendations:
            md += "## Long-term Recommendations\n\n"
            for i, rec in enumerate(self.long_term_recommendations, 1):
                md += f"{i}. {rec}\n"
            md += "\n"
        
        md += f"---\n*Confidence Level: {self.confidence_level}*\n"
        if self.analysis_limitations:
            md += "\n*Limitations:*\n"
            for lim in self.analysis_limitations:
                md += f"- {lim}\n"
        
        return md


class AnalysisResult(BaseModel):
    """Complete AI analysis result container."""
    
    # Source information
    source_file: str
    hostname: str | None = None
    analysis_start: datetime
    analysis_end: datetime
    
    # Results
    anomaly_report: AnomalyReport | None = None
    incident_summary: IncidentSummary | None = None
    query_results: list[QueryResult] = Field(default_factory=list)
    
    # Metadata
    model_used: str
    total_tokens: int = 0
    artifacts_processed: int = 0
    
    @property
    def duration_seconds(self) -> float:
        """Analysis duration in seconds."""
        return (self.analysis_end - self.analysis_start).total_seconds()
