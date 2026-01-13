"""
Preprocessor for UAC artifacts.

Normalizes and chunks parsed artifacts into LLM-friendly formats
for vector storage and RAG queries.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from uac_ai_parser.models.artifacts import (
    UACOutput,
    BodyfileEntry,
    ProcessInfo,
    NetworkConnection,
    UserInfo,
    TimelineEvent,
    LogEntry,
)

logger = logging.getLogger(__name__)


@dataclass
class DocumentChunk:
    """A chunk of document ready for embedding."""
    
    chunk_id: str
    content: str
    metadata: dict[str, Any]
    source: str
    source_type: str
    
    # For retrieval
    artifact_type: str
    timestamp: datetime | None = None
    relevance_tags: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "chunk_id": self.chunk_id,
            "content": self.content,
            "metadata": self.metadata,
            "source": self.source,
            "source_type": self.source_type,
            "artifact_type": self.artifact_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "relevance_tags": self.relevance_tags,
        }


class Preprocessor:
    """
    Preprocessor for UAC artifacts.
    
    Transforms parsed UAC data into chunks suitable for:
    - Vector embedding and storage
    - LLM context windows
    - Semantic search
    
    Example:
        ```python
        preprocessor = Preprocessor(chunk_size=2000, chunk_overlap=200)
        chunks = preprocessor.process(uac_output)
        
        for chunk in chunks:
            # Add to vector store
            vector_store.add(chunk.content, chunk.metadata)
        ```
    """
    
    # Tags for categorizing content
    SECURITY_TAGS = {
        "lateral_movement": ["ssh", "rdp", "psexec", "wmic", "winrm", "smbexec"],
        "persistence": ["cron", "systemd", "rc.local", "init.d", "bashrc", "profile"],
        "privilege_escalation": ["sudo", "su ", "setuid", "setgid", "capabilities"],
        "credential_access": ["passwd", "shadow", "mimikatz", "keylog", "dump"],
        "defense_evasion": ["hidden", "deleted", "rootkit", "ld_preload", "ptrace"],
        "exfiltration": ["curl", "wget", "nc ", "netcat", "base64", "encode"],
        "execution": ["bash", "python", "perl", "php", "ruby", "node"],
        "discovery": ["whoami", "id ", "uname", "ifconfig", "netstat", "ps "],
    }
    
    def __init__(
        self,
        chunk_size: int = 1500,
        chunk_overlap: int = 200,
        include_metadata: bool = True,
        max_chunks_per_type: int = 1000,
    ):
        """
        Initialize preprocessor.
        
        Args:
            chunk_size: Maximum characters per chunk
            chunk_overlap: Overlap between consecutive chunks
            include_metadata: Whether to include metadata in chunks
            max_chunks_per_type: Limit chunks per artifact type
        """
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.include_metadata = include_metadata
        self.max_chunks_per_type = max_chunks_per_type
    
    def process(self, uac_output: UACOutput) -> list[DocumentChunk]:
        """
        Process UAC output into document chunks.
        
        Args:
            uac_output: Parsed UAC output
            
        Returns:
            List of document chunks ready for embedding
        """
        logger.info("Preprocessing UAC output for LLM consumption")
        
        all_chunks = []
        
        # Process each artifact type
        all_chunks.extend(self._process_bodyfile(uac_output))
        all_chunks.extend(self._process_processes(uac_output))
        all_chunks.extend(self._process_network(uac_output))
        all_chunks.extend(self._process_users(uac_output))
        all_chunks.extend(self._process_timeline(uac_output))
        all_chunks.extend(self._process_logs(uac_output))
        all_chunks.extend(self._process_summary(uac_output))
        
        logger.info(f"Generated {len(all_chunks)} document chunks")
        return all_chunks
    
    def _generate_chunk_id(self, content: str, prefix: str) -> str:
        """Generate unique chunk ID."""
        import uuid
        # Use full content hash + random UUID to ensure global uniqueness
        hash_input = content.encode()
        content_hash = hashlib.md5(hash_input).hexdigest()[:8]
        return f"{prefix}_{content_hash}_{str(uuid.uuid4())[:8]}"
    
    def _tag_content(self, content: str) -> list[str]:
        """Add security-relevant tags to content."""
        tags = []
        content_lower = content.lower()
        
        for tag, keywords in self.SECURITY_TAGS.items():
            if any(kw in content_lower for kw in keywords):
                tags.append(tag)
        
        return tags
    
    def _chunk_text(self, text: str, prefix: str = "") -> Iterator[str]:
        """Split text into overlapping chunks."""
        if len(text) <= self.chunk_size:
            yield text
            return
        
        start = 0
        while start < len(text):
            end = start + self.chunk_size
            
            # Try to break at newline or space
            if end < len(text):
                # Look for newline first
                newline_pos = text.rfind("\n", start, end)
                if newline_pos > start + self.chunk_size // 2:
                    end = newline_pos + 1
                else:
                    # Fall back to space
                    space_pos = text.rfind(" ", start, end)
                    if space_pos > start + self.chunk_size // 2:
                        end = space_pos + 1
            
            chunk = text[start:end].strip()
            if chunk:
                yield chunk
            
            start = end - self.chunk_overlap
            if start < 0:
                start = 0
    
    def _process_summary(self, uac_output: UACOutput) -> list[DocumentChunk]:
        """Create summary chunk for quick context."""
        chunks = []
        
        summary = f"""# System Analysis Summary

## System Information
- Hostname: {uac_output.hostname or 'Unknown'}
- OS Type: {uac_output.os_type or 'Unknown'}
- Collection Time: {uac_output.collection_time.isoformat() if uac_output.collection_time else 'Unknown'}

## Artifact Counts
- Total Files: {uac_output.bodyfile.total_entries if uac_output.bodyfile else 0}
- Executable Files: {len(uac_output.bodyfile.executables) if uac_output.bodyfile else 0}
- SUID/SGID Files: {len(uac_output.bodyfile.setuid_files) if uac_output.bodyfile else 0}
- Running Processes: {len(uac_output.live_response.processes) if uac_output.live_response else 0}
- Network Connections: {len(uac_output.live_response.network_connections) if uac_output.live_response else 0}
- User Accounts: {len(uac_output.live_response.users) if uac_output.live_response else 0}
- Log Entries: {len(uac_output.logs)}
- Timeline Events: {len(uac_output.timeline)}

## Key Findings Preview
"""
        
        # Add notable findings
        if uac_output.bodyfile and uac_output.bodyfile.setuid_files:
            summary += "\n### SUID/SGID Files (Potential Privilege Escalation)\n"
            for entry in uac_output.bodyfile.setuid_files[:10]:
                summary += f"- {entry.name} ({entry.mode})\n"
        
        if uac_output.live_response:
            # Processes without binaries
            procs_no_binary = [
                p for p in uac_output.live_response.processes 
                if p.binary_exists is False
            ]
            if procs_no_binary:
                summary += "\n### Processes Without Binary on Disk\n"
                for proc in procs_no_binary[:10]:
                    summary += f"- PID {proc.pid}: {proc.command[:50]}\n"
            
            # Listening services
            listening = [
                c for c in uac_output.live_response.network_connections 
                if c.is_listening
            ]
            if listening:
                summary += "\n### Listening Services\n"
                for conn in listening[:15]:
                    summary += f"- {conn.protocol} {conn.local_address}:{conn.local_port}"
                    if conn.program:
                        summary += f" ({conn.program})"
                    summary += "\n"
        
        chunk = DocumentChunk(
            chunk_id=self._generate_chunk_id(summary, "summary"),
            content=summary,
            metadata={
                "hostname": uac_output.hostname,
                "collection_time": uac_output.collection_time.isoformat() if uac_output.collection_time else None,
            },
            source="summary",
            source_type="summary",
            artifact_type="summary",
            relevance_tags=["overview", "summary"],
        )
        chunks.append(chunk)
        
        return chunks
    
    def _process_bodyfile(self, uac_output: UACOutput) -> list[DocumentChunk]:
        """Process bodyfile entries into chunks."""
        chunks = []
        
        if not uac_output.bodyfile:
            return chunks
        
        # Group entries by category for better context
        categories = {
            "executables": uac_output.bodyfile.executables,
            "setuid": uac_output.bodyfile.setuid_files,
            "suspicious_locations": [
                e for e in uac_output.bodyfile.entries
                if any(p in e.name for p in ["/tmp/", "/var/tmp/", "/dev/shm/", "/."])
            ],
        }
        
        for category, entries in categories.items():
            if not entries:
                continue
            
            content_lines = [f"# Bodyfile Analysis: {category.title()}\n"]
            
            for entry in entries[:self.max_chunks_per_type]:
                line = f"- {entry.name}\n"
                line += f"  Mode: {entry.mode}, Size: {entry.size}, "
                line += f"UID: {entry.uid}, GID: {entry.gid}\n"
                if entry.md5 and entry.md5 != "0":
                    line += f"  MD5: {entry.md5}\n"
                if entry.mtime_dt:
                    line += f"  Modified: {entry.mtime_dt.isoformat()}\n"
                content_lines.append(line)
            
            content = "".join(content_lines)
            
            for chunk_text in self._chunk_text(content, f"bodyfile_{category}"):
                chunk = DocumentChunk(
                    chunk_id=self._generate_chunk_id(chunk_text, f"bodyfile_{category}"),
                    content=chunk_text,
                    metadata={
                        "category": category,
                        "entry_count": len(entries),
                    },
                    source="bodyfile.txt",
                    source_type="filesystem",
                    artifact_type="bodyfile",
                    relevance_tags=self._tag_content(chunk_text) + [category],
                )
                chunks.append(chunk)
        
        return chunks
    
    def _process_processes(self, uac_output: UACOutput) -> list[DocumentChunk]:
        """Process process information into chunks."""
        chunks = []
        
        if not uac_output.live_response or not uac_output.live_response.processes:
            return chunks
        
        processes = uac_output.live_response.processes
        
        # Group by characteristics
        groups = {
            "all": processes[:self.max_chunks_per_type],
            "root": [p for p in processes if p.user == "root"][:200],
            "high_cpu": sorted(
                [p for p in processes if p.cpu and p.cpu > 10],
                key=lambda x: x.cpu or 0, reverse=True
            )[:50],
            "high_mem": sorted(
                [p for p in processes if p.mem and p.mem > 5],
                key=lambda x: x.mem or 0, reverse=True
            )[:50],
        }
        
        for group_name, group_procs in groups.items():
            if not group_procs:
                continue
            
            content_lines = [f"# Running Processes: {group_name.replace('_', ' ').title()}\n\n"]
            
            for proc in group_procs:
                line = f"PID: {proc.pid}"
                if proc.ppid:
                    line += f", PPID: {proc.ppid}"
                if proc.user:
                    line += f", User: {proc.user}"
                if proc.cpu:
                    line += f", CPU: {proc.cpu}%"
                if proc.mem:
                    line += f", MEM: {proc.mem}%"
                line += f"\nCommand: {proc.command}\n\n"
                content_lines.append(line)
            
            content = "".join(content_lines)
            
            for chunk_text in self._chunk_text(content, f"processes_{group_name}"):
                chunk = DocumentChunk(
                    chunk_id=self._generate_chunk_id(chunk_text, f"proc_{group_name}"),
                    content=chunk_text,
                    metadata={
                        "group": group_name,
                        "process_count": len(group_procs),
                    },
                    source="ps_output",
                    source_type="live_response",
                    artifact_type="process",
                    relevance_tags=self._tag_content(chunk_text) + ["process", group_name],
                )
                chunks.append(chunk)
        
        return chunks
    
    def _process_network(self, uac_output: UACOutput) -> list[DocumentChunk]:
        """Process network connections into chunks."""
        chunks = []
        
        if not uac_output.live_response or not uac_output.live_response.network_connections:
            return chunks
        
        connections = uac_output.live_response.network_connections
        
        # Group by state
        groups = {
            "listening": [c for c in connections if c.is_listening],
            "established": [c for c in connections if c.is_established],
            "all": connections[:self.max_chunks_per_type],
        }
        
        for group_name, group_conns in groups.items():
            if not group_conns:
                continue
            
            content_lines = [f"# Network Connections: {group_name.title()}\n\n"]
            
            for conn in group_conns[:500]:
                line = f"{conn.protocol.upper()} "
                line += f"{conn.local_address}:{conn.local_port}"
                if conn.remote_address:
                    line += f" -> {conn.remote_address}:{conn.remote_port}"
                if conn.state:
                    line += f" [{conn.state}]"
                if conn.pid:
                    line += f" PID:{conn.pid}"
                if conn.program:
                    line += f" ({conn.program})"
                line += "\n"
                content_lines.append(line)
            
            content = "".join(content_lines)
            
            for chunk_text in self._chunk_text(content, f"network_{group_name}"):
                chunk = DocumentChunk(
                    chunk_id=self._generate_chunk_id(chunk_text, f"net_{group_name}"),
                    content=chunk_text,
                    metadata={
                        "group": group_name,
                        "connection_count": len(group_conns),
                    },
                    source="netstat_output",
                    source_type="live_response",
                    artifact_type="network",
                    relevance_tags=self._tag_content(chunk_text) + ["network", group_name],
                )
                chunks.append(chunk)
        
        return chunks
    
    def _process_users(self, uac_output: UACOutput) -> list[DocumentChunk]:
        """Process user information into chunks."""
        chunks = []
        
        if not uac_output.live_response or not uac_output.live_response.users:
            return chunks
        
        users = uac_output.live_response.users
        
        content_lines = ["# User Accounts\n\n"]
        
        # Regular users (non-system)
        content_lines.append("## Regular Users\n")
        for user in users:
            if not user.is_system_user:
                line = f"- {user.username} (UID: {user.uid})\n"
                line += f"  Home: {user.home}, Shell: {user.shell}\n"
                if not user.has_valid_shell:
                    line += "  ⚠️ No valid login shell\n"
                content_lines.append(line)
        
        # System users with shells
        content_lines.append("\n## System Users with Valid Shells\n")
        for user in users:
            if user.is_system_user and user.has_valid_shell:
                line = f"- {user.username} (UID: {user.uid})\n"
                line += f"  Home: {user.home}, Shell: {user.shell}\n"
                content_lines.append(line)
        
        content = "".join(content_lines)
        
        # Add a "keywords" section to help semantic retrieval for broad queries
        content += "\n\nKeywords: list of users, usernames, user accounts, login accounts, system users, /etc/passwd content"
        
        chunk = DocumentChunk(
            chunk_id=self._generate_chunk_id(content, "users"),
            content=content,
            metadata={"user_count": len(users)},
            source="passwd",
            source_type="live_response",
            artifact_type="user",
            relevance_tags=self._tag_content(content) + ["user", "account", "passwd"],
        )
        chunks.append(chunk)
        
        return chunks
    
    def _process_timeline(self, uac_output: UACOutput) -> list[DocumentChunk]:
        """Process timeline events into chunks."""
        chunks = []
        
        if not uac_output.timeline:
            return chunks
        
        events = uac_output.timeline
        
        # Group events by hour for better context
        from collections import defaultdict
        hourly_events: dict[str, list[TimelineEvent]] = defaultdict(list)
        
        for event in events:
            hour_key = event.timestamp.strftime("%Y-%m-%d %H:00")
            hourly_events[hour_key].append(event)
        
        # Create chunks for each hour
        for hour, hour_events in list(hourly_events.items())[:self.max_chunks_per_type]:
            content_lines = [f"# Timeline Events: {hour}\n\n"]
            
            for event in hour_events[:100]:
                line = f"[{event.timestamp.strftime('%H:%M:%S')}] "
                line += f"[{event.source_type}] {event.message[:200]}\n"
                if event.artifact_path:
                    line += f"  Source: {event.artifact_path}\n"
                content_lines.append(line)
            
            content = "".join(content_lines)
            
            chunk = DocumentChunk(
                chunk_id=self._generate_chunk_id(content, f"timeline_{hour}"),
                content=content,
                metadata={
                    "hour": hour,
                    "event_count": len(hour_events),
                },
                source="timeline",
                source_type="timeline",
                artifact_type="timeline",
                timestamp=hour_events[0].timestamp if hour_events else None,
                relevance_tags=self._tag_content(content) + ["timeline"],
            )
            chunks.append(chunk)
        
        return chunks
    
    def _process_logs(self, uac_output: UACOutput) -> list[DocumentChunk]:
        """Process log entries into chunks."""
        chunks = []
        
        if not uac_output.logs:
            return chunks
        
        # Group by source file
        from collections import defaultdict
        logs_by_source: dict[str, list[LogEntry]] = defaultdict(list)
        
        for log in uac_output.logs:
            source_name = Path(log.source_file).name
            logs_by_source[source_name].append(log)
        
        for source, entries in logs_by_source.items():
            if len(chunks) >= self.max_chunks_per_type:
                break
            
            content_lines = [f"# Log File: {source}\n\n"]
            
            for entry in entries[:500]:
                if entry.timestamp:
                    line = f"[{entry.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] "
                else:
                    line = "[Unknown Time] "
                line += f"{entry.message or entry.raw_line[:200]}\n"
                content_lines.append(line)
            
            content = "".join(content_lines)
            
            for chunk_text in self._chunk_text(content, f"log_{source}"):
                chunk = DocumentChunk(
                    chunk_id=self._generate_chunk_id(chunk_text, f"log_{source}"),
                    content=chunk_text,
                    metadata={
                        "source_file": source,
                        "entry_count": len(entries),
                    },
                    source=source,
                    source_type="log",
                    artifact_type="log",
                    relevance_tags=self._tag_content(chunk_text) + ["log", source.replace(".", "_")],
                )
                chunks.append(chunk)
                
                if len(chunks) >= self.max_chunks_per_type:
                    break
        
        return chunks
    
    def to_jsonl(self, chunks: list[DocumentChunk], output_path: str | Path) -> None:
        """Export chunks to JSONL format."""
        with open(output_path, "w", encoding="utf-8") as f:
            for chunk in chunks:
                f.write(json.dumps(chunk.to_dict()) + "\n")
        
        logger.info(f"Exported {len(chunks)} chunks to {output_path}")
    
    def to_json(self, chunks: list[DocumentChunk], output_path: str | Path) -> None:
        """Export chunks to JSON format."""
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump([chunk.to_dict() for chunk in chunks], f, indent=2)
        
        logger.info(f"Exported {len(chunks)} chunks to {output_path}")
