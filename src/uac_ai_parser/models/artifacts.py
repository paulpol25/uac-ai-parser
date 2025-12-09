"""
Data models for UAC artifacts.

These models represent the various artifact types collected by UAC,
including bodyfiles, process information, network data, and more.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ArtifactCategory(str, Enum):
    """Categories of UAC artifacts."""
    
    LIVE_RESPONSE = "live_response"
    BODYFILE = "bodyfile"
    HASH = "hash"
    LOG = "log"
    CONFIG = "config"
    NETWORK = "network"
    PROCESS = "process"
    USER = "user"
    SYSTEM = "system"
    MEMORY = "memory"
    UNKNOWN = "unknown"


class BodyfileEntry(BaseModel):
    """
    A single entry from a TSK-compatible bodyfile.
    
    Bodyfile format (pipe-delimited):
    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime
    
    Times are Unix timestamps (seconds since epoch).
    """
    
    md5: str = Field(default="0", description="MD5 hash or 0 if not computed")
    name: str = Field(description="Full path of the file")
    inode: str = Field(default="0", description="Inode number")
    mode: str = Field(default="", description="File mode as string (e.g., -rwxr-xr-x)")
    uid: int = Field(default=0, description="User ID")
    gid: int = Field(default=0, description="Group ID")
    size: int = Field(default=0, description="File size in bytes")
    atime: int = Field(default=0, description="Access time (Unix timestamp)")
    mtime: int = Field(default=0, description="Modification time (Unix timestamp)")
    ctime: int = Field(default=0, description="Change time (Unix timestamp)")
    crtime: int = Field(default=0, description="Creation time (Unix timestamp)")
    
    @property
    def atime_dt(self) -> datetime | None:
        """Access time as datetime."""
        return datetime.fromtimestamp(self.atime) if self.atime > 0 else None
    
    @property
    def mtime_dt(self) -> datetime | None:
        """Modification time as datetime."""
        return datetime.fromtimestamp(self.mtime) if self.mtime > 0 else None
    
    @property
    def ctime_dt(self) -> datetime | None:
        """Change time as datetime."""
        return datetime.fromtimestamp(self.ctime) if self.ctime > 0 else None
    
    @property
    def crtime_dt(self) -> datetime | None:
        """Creation time as datetime."""
        return datetime.fromtimestamp(self.crtime) if self.crtime > 0 else None
    
    @property
    def is_executable(self) -> bool:
        """Check if file has executable permissions."""
        return "x" in self.mode
    
    @property
    def is_setuid(self) -> bool:
        """Check if file has SUID bit set."""
        return "s" in self.mode.lower() if self.mode else False
    
    @property
    def is_directory(self) -> bool:
        """Check if entry is a directory."""
        return self.mode.startswith("d") if self.mode else False
    
    @property
    def filename(self) -> str:
        """Extract just the filename from the path."""
        return Path(self.name).name
    
    @property
    def directory(self) -> str:
        """Extract the parent directory from the path."""
        return str(Path(self.name).parent)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "md5": self.md5,
            "name": self.name,
            "inode": self.inode,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "size": self.size,
            "atime": self.atime,
            "mtime": self.mtime,
            "ctime": self.ctime,
            "crtime": self.crtime,
            "atime_iso": self.atime_dt.isoformat() if self.atime_dt else None,
            "mtime_iso": self.mtime_dt.isoformat() if self.mtime_dt else None,
            "ctime_iso": self.ctime_dt.isoformat() if self.ctime_dt else None,
            "crtime_iso": self.crtime_dt.isoformat() if self.crtime_dt else None,
        }
    
    @classmethod
    def from_line(cls, line: str) -> "BodyfileEntry":
        """Parse a bodyfile line into an entry."""
        parts = line.strip().split("|")
        if len(parts) < 11:
            # Pad with defaults if line is incomplete
            parts.extend(["0"] * (11 - len(parts)))
        
        return cls(
            md5=parts[0] or "0",
            name=parts[1] or "",
            inode=parts[2] or "0",
            mode=parts[3] or "",
            uid=int(parts[4]) if parts[4].isdigit() else 0,
            gid=int(parts[5]) if parts[5].isdigit() else 0,
            size=int(parts[6]) if parts[6].isdigit() else 0,
            atime=int(parts[7]) if parts[7].isdigit() else 0,
            mtime=int(parts[8]) if parts[8].isdigit() else 0,
            ctime=int(parts[9]) if parts[9].isdigit() else 0,
            crtime=int(parts[10]) if parts[10].isdigit() else 0,
        )


class Bodyfile(BaseModel):
    """Collection of bodyfile entries with analysis helpers."""
    
    entries: list[BodyfileEntry] = Field(default_factory=list)
    source_file: str | None = None
    
    @property
    def total_entries(self) -> int:
        """Total number of entries."""
        return len(self.entries)
    
    @property
    def executables(self) -> list[BodyfileEntry]:
        """Filter for executable files."""
        return [e for e in self.entries if e.is_executable and not e.is_directory]
    
    @property
    def setuid_files(self) -> list[BodyfileEntry]:
        """Filter for SUID/SGID files."""
        return [e for e in self.entries if e.is_setuid]
    
    @property
    def directories(self) -> list[BodyfileEntry]:
        """Filter for directories."""
        return [e for e in self.entries if e.is_directory]
    
    @property
    def files_with_hash(self) -> list[BodyfileEntry]:
        """Filter for files that have an MD5 hash."""
        return [e for e in self.entries if e.md5 != "0" and e.md5 != ""]
    
    def filter_by_path(self, pattern: str) -> list[BodyfileEntry]:
        """Filter entries by path pattern."""
        import fnmatch
        return [e for e in self.entries if fnmatch.fnmatch(e.name, pattern)]
    
    def filter_by_timerange(
        self, 
        start: datetime | None = None, 
        end: datetime | None = None,
        time_type: str = "mtime"
    ) -> list[BodyfileEntry]:
        """Filter entries by time range."""
        results = []
        for entry in self.entries:
            timestamp = getattr(entry, time_type, 0)
            if timestamp <= 0:
                continue
            entry_time = datetime.fromtimestamp(timestamp)
            if start and entry_time < start:
                continue
            if end and entry_time > end:
                continue
            results.append(entry)
        return results
    
    def to_dataframe(self) -> "pd.DataFrame":
        """Convert to pandas DataFrame for analysis."""
        import pandas as pd
        return pd.DataFrame([e.to_dict() for e in self.entries])
    
    @classmethod
    def from_file(cls, filepath: str | Path) -> "Bodyfile":
        """Parse a bodyfile from disk."""
        entries = []
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        entries.append(BodyfileEntry.from_line(line))
                    except Exception:
                        continue  # Skip malformed lines
        return cls(entries=entries, source_file=str(filepath))


class TimelineEvent(BaseModel):
    """A single event in a forensic timeline."""
    
    timestamp: datetime
    timestamp_desc: str = Field(description="Description of timestamp type (e.g., 'File Modified')")
    source: str = Field(description="Source of the event (file, log, process, etc.)")
    source_type: str = Field(default="unknown", description="Type categorization")
    event_type: str = Field(default="", description="Event type/action")
    message: str = Field(description="Human-readable event description")
    artifact_path: str | None = Field(default=None, description="Path to source artifact")
    
    # Additional metadata
    hostname: str | None = None
    username: str | None = None
    pid: int | None = None
    extra_data: dict[str, Any] = Field(default_factory=dict)
    
    # AI-added fields
    anomaly_score: float | None = Field(default=None, ge=0, le=1)
    anomaly_reason: str | None = None
    
    def to_timesketch_format(self) -> dict[str, Any]:
        """Convert to Timesketch-compatible format."""
        return {
            "datetime": self.timestamp.isoformat(),
            "timestamp_desc": self.timestamp_desc,
            "message": self.message,
            "source_short": self.source_type,
            "source_long": self.source,
            "data_type": f"uac:{self.source_type}",
            **self.extra_data,
        }


class ProcessInfo(BaseModel):
    """Information about a running process."""
    
    pid: int
    ppid: int | None = None
    user: str | None = None
    cpu: float | None = None
    mem: float | None = None
    vsz: int | None = None
    rss: int | None = None
    tty: str | None = None
    stat: str | None = None
    start: str | None = None
    time: str | None = None
    command: str = Field(description="Full command line")
    
    # Derived from other artifacts
    binary_path: str | None = None
    binary_exists: bool | None = None
    binary_hash: str | None = None
    cwd: str | None = None
    open_files: list[str] = Field(default_factory=list)
    network_connections: list[str] = Field(default_factory=list)
    
    # AI analysis
    anomaly_score: float | None = Field(default=None, ge=0, le=1)
    anomaly_flags: list[str] = Field(default_factory=list)
    
    @property
    def executable_name(self) -> str:
        """Extract executable name from command."""
        if self.command:
            return self.command.split()[0].split("/")[-1]
        return ""


class NetworkConnection(BaseModel):
    """Network connection information."""
    
    protocol: str = Field(description="tcp, udp, tcp6, udp6")
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    state: str | None = None
    pid: int | None = None
    program: str | None = None
    user: str | None = None
    
    # AI analysis
    anomaly_score: float | None = Field(default=None, ge=0, le=1)
    anomaly_reason: str | None = None
    
    @property
    def is_listening(self) -> bool:
        """Check if connection is in listening state."""
        return self.state and self.state.upper() == "LISTEN"
    
    @property
    def is_established(self) -> bool:
        """Check if connection is established."""
        return self.state and self.state.upper() == "ESTABLISHED"


class UserInfo(BaseModel):
    """User account information."""
    
    username: str
    uid: int
    gid: int
    home: str | None = None
    shell: str | None = None
    gecos: str | None = None
    groups: list[str] = Field(default_factory=list)
    
    # Login history
    last_login: datetime | None = None
    login_history: list[dict[str, Any]] = Field(default_factory=list)
    
    # Analysis
    is_system_user: bool = False
    has_valid_shell: bool = True
    anomaly_flags: list[str] = Field(default_factory=list)


class HashEntry(BaseModel):
    """Hash information for a file."""
    
    filepath: str
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    size: int | None = None
    
    # Threat intel integration (future)
    vt_detected: bool | None = None
    vt_score: str | None = None


class LogEntry(BaseModel):
    """Parsed log entry."""
    
    timestamp: datetime | None
    source_file: str
    raw_line: str
    parsed: dict[str, Any] = Field(default_factory=dict)
    
    # Classification
    log_type: str = Field(default="unknown")
    severity: str | None = None
    facility: str | None = None
    
    # Extracted entities
    username: str | None = None
    hostname: str | None = None
    ip_address: str | None = None
    pid: int | None = None
    message: str | None = None


@dataclass
class LiveResponseArtifacts:
    """Container for live response artifacts."""
    
    processes: list[ProcessInfo] = field(default_factory=list)
    network_connections: list[NetworkConnection] = field(default_factory=list)
    users: list[UserInfo] = field(default_factory=list)
    loaded_modules: list[dict[str, Any]] = field(default_factory=list)
    open_files: list[dict[str, Any]] = field(default_factory=list)
    system_info: dict[str, Any] = field(default_factory=dict)
    raw_outputs: dict[str, str] = field(default_factory=dict)


@dataclass
class UACOutput:
    """
    Complete parsed UAC output.
    
    This is the main container for all artifacts extracted from a UAC
    tar.gz/zip output file.
    """
    
    # Metadata
    source_file: str
    hostname: str | None = None
    os_type: str | None = None
    collection_time: datetime | None = None
    uac_version: str | None = None
    profile_used: str | None = None
    
    # Artifact containers
    bodyfile: Bodyfile | None = None
    live_response: LiveResponseArtifacts | None = None
    hash_data: list[HashEntry] = field(default_factory=list)
    logs: list[LogEntry] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    
    # Raw artifact paths for reference
    artifact_paths: dict[str, list[str]] = field(default_factory=dict)
    
    # Configuration files collected
    config_files: dict[str, str] = field(default_factory=dict)
    
    # Structured JSON for LLM consumption
    structured_data: dict[str, Any] = field(default_factory=dict)
    
    def get_artifacts_by_category(self, category: ArtifactCategory) -> list[Any]:
        """Get all artifacts of a specific category."""
        mapping = {
            ArtifactCategory.BODYFILE: [self.bodyfile] if self.bodyfile else [],
            ArtifactCategory.PROCESS: self.live_response.processes if self.live_response else [],
            ArtifactCategory.NETWORK: self.live_response.network_connections if self.live_response else [],
            ArtifactCategory.USER: self.live_response.users if self.live_response else [],
            ArtifactCategory.HASH: self.hash_data,
            ArtifactCategory.LOG: self.logs,
        }
        return mapping.get(category, [])
    
    def to_json(self) -> dict[str, Any]:
        """Serialize to JSON-compatible dictionary."""
        return {
            "metadata": {
                "source_file": self.source_file,
                "hostname": self.hostname,
                "os_type": self.os_type,
                "collection_time": self.collection_time.isoformat() if self.collection_time else None,
                "uac_version": self.uac_version,
                "profile_used": self.profile_used,
            },
            "bodyfile": {
                "total_entries": self.bodyfile.total_entries if self.bodyfile else 0,
                "executables": len(self.bodyfile.executables) if self.bodyfile else 0,
                "setuid_files": len(self.bodyfile.setuid_files) if self.bodyfile else 0,
            },
            "live_response": {
                "processes": len(self.live_response.processes) if self.live_response else 0,
                "network_connections": len(self.live_response.network_connections) if self.live_response else 0,
                "users": len(self.live_response.users) if self.live_response else 0,
            },
            "hash_entries": len(self.hash_data),
            "log_entries": len(self.logs),
            "timeline_events": len(self.timeline),
        }
