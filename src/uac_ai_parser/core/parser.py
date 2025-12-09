"""
UAC Parser - Main parsing module.

Orchestrates extraction, parsing, and preprocessing of UAC outputs
into structured data ready for AI analysis.

Supports both UAC 2.x (raw text files) and UAC 3.x (YAML structured output).
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from uac_ai_parser.core.extractor import UACExtractor, ExtractionResult
from uac_ai_parser.core.preprocessor import Preprocessor
from uac_ai_parser.models.artifacts import (
    UACOutput,
    Bodyfile,
    BodyfileEntry,
    LiveResponseArtifacts,
    ProcessInfo,
    NetworkConnection,
    UserInfo,
    HashEntry,
    LogEntry,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


class UACParser:
    """
    Main parser for UAC output archives.
    
    Handles complete parsing pipeline from archive extraction through
    structured data generation for AI analysis.
    
    Example:
        ```python
        parser = UACParser("/path/to/uac-output.tar.gz")
        artifacts = parser.parse()
        
        # Access parsed data
        print(f"Hostname: {artifacts.hostname}")
        print(f"Processes: {len(artifacts.live_response.processes)}")
        print(f"Bodyfile entries: {artifacts.bodyfile.total_entries}")
        ```
    """
    
    def __init__(
        self,
        archive_path: str | Path,
        extract_dir: str | Path | None = None,
        parse_logs: bool = True,
        generate_timeline: bool = True,
        max_log_entries: int = 100000,
    ):
        """
        Initialize the parser.
        
        Args:
            archive_path: Path to UAC output archive
            extract_dir: Directory to extract to (temp if None)
            parse_logs: Whether to parse log files
            generate_timeline: Whether to generate timeline events
            max_log_entries: Maximum log entries to parse (memory limit)
        """
        self.archive_path = Path(archive_path)
        self.extract_dir = Path(extract_dir) if extract_dir else None
        self.parse_logs = parse_logs
        self.generate_timeline = generate_timeline
        self.max_log_entries = max_log_entries
        
        self._extractor: UACExtractor | None = None
        self._extraction_result: ExtractionResult | None = None
        self._parsed: UACOutput | None = None
    
    def parse(self) -> UACOutput:
        """
        Parse the UAC archive completely.
        
        Returns:
            UACOutput containing all parsed artifacts
        """
        logger.info(f"Starting UAC parse: {self.archive_path}")
        start_time = datetime.now()
        
        # Extract archive
        self._extractor = UACExtractor(
            self.archive_path,
            self.extract_dir,
            cleanup_on_error=True,
        )
        self._extraction_result = self._extractor.extract()
        
        # Initialize output container
        self._parsed = UACOutput(
            source_file=str(self.archive_path),
            hostname=self._extraction_result.hostname,
            os_type=self._extraction_result.os_type,
            collection_time=self._parse_collection_time(),
        )
        
        # Parse each artifact category
        self._parse_bodyfile()
        self._parse_live_response()
        self._parse_hash_files()
        
        if self.parse_logs:
            self._parse_logs()
        
        if self.generate_timeline:
            self._build_timeline()
        
        # Generate structured data for LLM
        self._generate_structured_data()
        
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Parse complete in {duration:.2f}s")
        
        return self._parsed
    
    def _parse_collection_time(self) -> datetime | None:
        """Parse collection timestamp from UAC metadata."""
        if self._extraction_result and self._extraction_result.collection_time:
            try:
                # UAC format: YYYYMMDDHHMMSS
                ts = self._extraction_result.collection_time
                return datetime.strptime(ts, "%Y%m%d%H%M%S")
            except ValueError:
                pass
        return None
    
    def _parse_bodyfile(self) -> None:
        """Parse bodyfile.txt if present."""
        if not self._extraction_result or not self._extraction_result.bodyfile_path:
            logger.debug("No bodyfile found in UAC output")
            return
        
        bodyfile_path = Path(self._extraction_result.bodyfile_path)
        if not bodyfile_path.exists():
            return
        
        logger.info(f"Parsing bodyfile: {bodyfile_path}")
        
        try:
            self._parsed.bodyfile = Bodyfile.from_file(bodyfile_path)
            logger.info(f"Parsed {self._parsed.bodyfile.total_entries} bodyfile entries")
        except Exception as e:
            logger.error(f"Failed to parse bodyfile: {e}")
    
    def _parse_live_response(self) -> None:
        """Parse live response artifacts (supports both UAC 2.x and 3.x formats)."""
        if not self._extraction_result:
            return
        
        live_response = LiveResponseArtifacts()
        
        for artifact_path in self._extraction_result.live_response_paths:
            path = Path(artifact_path)
            if not path.exists() or path.is_dir():
                continue
            
            path_lower = str(path).lower()
            filename_lower = path.name.lower()
            
            try:
                # UAC 3.x YAML format
                if filename_lower.endswith(".yaml") or filename_lower.endswith(".yml"):
                    self._parse_yaml_artifact(path, live_response)
                    continue
                
                # UAC 2.x text format - Parse process listings
                if "ps_" in filename_lower or filename_lower.startswith("ps"):
                    processes = self._parse_ps_output(path)
                    live_response.processes.extend(processes)
                
                # Parse network connections
                elif "netstat" in filename_lower or "ss_" in filename_lower:
                    connections = self._parse_network_output(path)
                    live_response.network_connections.extend(connections)
                
                # Parse user information
                elif "passwd" in filename_lower or "user" in filename_lower:
                    users = self._parse_user_output(path)
                    live_response.users.extend(users)
                
                # Store raw output for reference
                else:
                    with open(path, "r", errors="ignore") as f:
                        content = f.read()[:50000]  # Limit size
                    rel_path = str(path.relative_to(self._extractor.extract_dir))
                    live_response.raw_outputs[rel_path] = content
                    
            except Exception as e:
                logger.warning(f"Failed to parse {path}: {e}")
        
        self._parsed.live_response = live_response
        logger.info(
            f"Parsed live response: {len(live_response.processes)} processes, "
            f"{len(live_response.network_connections)} connections"
        )
    
    def _parse_yaml_artifact(self, path: Path, live_response: LiveResponseArtifacts) -> None:
        """Parse UAC 3.x YAML format artifacts."""
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            
            # UAC 3.x YAML can contain multiple documents
            docs = list(yaml.safe_load_all(content))
            
            filename_lower = path.name.lower()
            rel_path = str(path.relative_to(self._extractor.extract_dir))
            
            for doc in docs:
                if doc is None:
                    continue
                
                # Handle different artifact types based on path/filename
                if "process/ps" in rel_path.lower():
                    self._parse_yaml_ps(doc, live_response)
                elif "network/netstat" in rel_path.lower() or "network/ss" in rel_path.lower():
                    self._parse_yaml_network(doc, live_response)
                elif "network/" in rel_path.lower():
                    self._parse_yaml_network_generic(doc, live_response)
                elif "system/" in rel_path.lower():
                    self._store_yaml_raw(doc, rel_path, live_response)
                else:
                    # Store as raw for LLM analysis
                    self._store_yaml_raw(doc, rel_path, live_response)
                    
        except yaml.YAMLError as e:
            logger.warning(f"Failed to parse YAML {path}: {e}")
        except Exception as e:
            logger.warning(f"Error processing {path}: {e}")
    
    def _parse_yaml_ps(self, doc: dict | list, live_response: LiveResponseArtifacts) -> None:
        """Parse process info from YAML document."""
        if isinstance(doc, dict):
            # UAC 3.x often wraps output in a dict with 'output' key
            output = doc.get("output", doc)
            if isinstance(output, str):
                # Raw ps output stored as string - parse line by line
                for line in output.split("\n")[1:]:  # Skip header
                    proc = self._parse_ps_line(line)
                    if proc:
                        live_response.processes.append(proc)
            elif isinstance(output, list):
                for item in output:
                    if isinstance(item, dict):
                        proc = ProcessInfo(
                            pid=item.get("pid", 0),
                            ppid=item.get("ppid"),
                            user=item.get("user", item.get("uid", "")),
                            command=item.get("command", item.get("cmd", item.get("comm", ""))),
                            cpu=item.get("cpu", item.get("%cpu")),
                            mem=item.get("mem", item.get("%mem")),
                            vsz=item.get("vsz"),
                            rss=item.get("rss"),
                            tty=item.get("tty"),
                            stat=item.get("stat", item.get("state")),
                            start=item.get("start", item.get("started")),
                            time=item.get("time"),
                        )
                        live_response.processes.append(proc)
    
    def _parse_yaml_network(self, doc: dict | list, live_response: LiveResponseArtifacts) -> None:
        """Parse network connections from YAML document."""
        if isinstance(doc, dict):
            output = doc.get("output", doc)
            if isinstance(output, str):
                # Raw netstat output - parse line by line
                for line in output.split("\n"):
                    conn = self._parse_netstat_line(line)
                    if conn:
                        live_response.network_connections.append(conn)
            elif isinstance(output, list):
                for item in output:
                    if isinstance(item, dict):
                        conn = NetworkConnection(
                            protocol=item.get("proto", item.get("protocol", "tcp")),
                            local_address=item.get("local_address", item.get("local", "")),
                            local_port=item.get("local_port", 0),
                            remote_address=item.get("remote_address", item.get("foreign", "")),
                            remote_port=item.get("remote_port", 0),
                            state=item.get("state", ""),
                            pid=item.get("pid"),
                            program=item.get("program", item.get("process", "")),
                        )
                        live_response.network_connections.append(conn)
    
    def _parse_yaml_network_generic(self, doc: dict | list, live_response: LiveResponseArtifacts) -> None:
        """Parse generic network YAML (arp, ip, etc.)."""
        if isinstance(doc, dict):
            output = doc.get("output", doc)
            # Store as raw for now
            if output:
                live_response.raw_outputs[f"network_{id(doc)}"] = str(output)[:50000]
    
    def _store_yaml_raw(self, doc: dict | list, rel_path: str, live_response: LiveResponseArtifacts) -> None:
        """Store YAML content as raw output for LLM analysis."""
        if isinstance(doc, dict):
            output = doc.get("output", doc)
        else:
            output = doc
        
        if output:
            content = yaml.dump(output, default_flow_style=False) if not isinstance(output, str) else output
            live_response.raw_outputs[rel_path] = content[:50000]
    
    def _parse_ps_line(self, line: str) -> ProcessInfo | None:
        """Parse a single ps output line."""
        line = line.strip()
        if not line:
            return None
        
        parts = line.split(None, 10)
        if len(parts) < 2:
            return None
        
        try:
            # Try ps aux format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
            if len(parts) >= 11:
                return ProcessInfo(
                    user=parts[0],
                    pid=int(parts[1]) if parts[1].isdigit() else 0,
                    cpu=float(parts[2]) if parts[2].replace(".", "").isdigit() else None,
                    mem=float(parts[3]) if parts[3].replace(".", "").isdigit() else None,
                    vsz=int(parts[4]) if parts[4].isdigit() else None,
                    rss=int(parts[5]) if parts[5].isdigit() else None,
                    tty=parts[6],
                    stat=parts[7],
                    start=parts[8],
                    time=parts[9],
                    command=parts[10] if len(parts) > 10 else "",
                )
        except (ValueError, IndexError):
            pass
        return None
    
    def _parse_netstat_line(self, line: str) -> NetworkConnection | None:
        """Parse a single netstat output line."""
        line = line.strip()
        if not line or line.startswith("Active") or line.startswith("Proto"):
            return None
        
        parts = line.split()
        if len(parts) < 4:
            return None
        
        try:
            proto = parts[0]
            local = parts[3] if len(parts) > 3 else ""
            remote = parts[4] if len(parts) > 4 else ""
            state = parts[5] if len(parts) > 5 else ""
            
            # Parse address:port
            local_addr, local_port = self._parse_address_port(local)
            remote_addr, remote_port = self._parse_address_port(remote)
            
            return NetworkConnection(
                protocol=proto,
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                state=state,
            )
        except (ValueError, IndexError):
            pass
        return None
    
    def _parse_address_port(self, addr_port: str) -> tuple[str, int]:
        """Parse address:port string."""
        if ":" in addr_port:
            parts = addr_port.rsplit(":", 1)
            addr = parts[0]
            try:
                port = int(parts[1]) if parts[1].isdigit() else 0
            except ValueError:
                port = 0
            return addr, port
        return addr_port, 0

    def _parse_ps_output(self, path: Path) -> list[ProcessInfo]:
        """Parse ps command output (UAC 2.x text format)."""
        processes = []
        
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
        
        if not lines:
            return processes
        
        # Detect format from header
        header = lines[0].lower() if lines else ""
        
        for line in lines[1:]:  # Skip header
            line = line.strip()
            if not line:
                continue
            
            parts = line.split(None, 10)  # Split into max 11 parts
            if len(parts) < 2:
                continue
            
            try:
                # Handle different ps formats
                if "aux" in path.name.lower():
                    # ps aux format: USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND
                    if len(parts) >= 11:
                        proc = ProcessInfo(
                            user=parts[0],
                            pid=int(parts[1]),
                            cpu=float(parts[2]) if parts[2].replace(".", "").isdigit() else None,
                            mem=float(parts[3]) if parts[3].replace(".", "").isdigit() else None,
                            vsz=int(parts[4]) if parts[4].isdigit() else None,
                            rss=int(parts[5]) if parts[5].isdigit() else None,
                            tty=parts[6],
                            stat=parts[7],
                            start=parts[8],
                            time=parts[9],
                            command=parts[10] if len(parts) > 10 else "",
                        )
                        processes.append(proc)
                elif "ef" in path.name.lower():
                    # ps -ef format: UID PID PPID C STIME TTY TIME CMD
                    if len(parts) >= 8:
                        proc = ProcessInfo(
                            user=parts[0],
                            pid=int(parts[1]),
                            ppid=int(parts[2]) if parts[2].isdigit() else None,
                            start=parts[4],
                            tty=parts[5],
                            time=parts[6],
                            command=" ".join(parts[7:]),
                        )
                        processes.append(proc)
                else:
                    # Generic: try to extract at least PID and command
                    for i, part in enumerate(parts):
                        if part.isdigit() and int(part) > 0:
                            proc = ProcessInfo(
                                pid=int(part),
                                command=" ".join(parts[i+1:]) if i+1 < len(parts) else "",
                            )
                            processes.append(proc)
                            break
                            
            except (ValueError, IndexError) as e:
                continue
        
        return processes
    
    def _parse_network_output(self, path: Path) -> list[NetworkConnection]:
        """Parse netstat/ss output."""
        connections = []
        
        with open(path, "r", errors="ignore") as f:
            lines = f.readlines()
        
        for line in lines[1:]:  # Skip header
            line = line.strip()
            if not line:
                continue
            
            parts = line.split()
            if len(parts) < 4:
                continue
            
            try:
                # netstat -tulpn format: Proto Recv-Q Send-Q Local Foreign State PID/Program
                # ss format similar
                proto = parts[0].lower()
                if proto not in ("tcp", "tcp6", "udp", "udp6"):
                    continue
                
                local = parts[3] if len(parts) > 3 else ""
                remote = parts[4] if len(parts) > 4 else ""
                state = parts[5] if len(parts) > 5 and not "/" in parts[5] else None
                
                # Parse addresses
                local_addr, local_port = self._parse_address(local)
                remote_addr, remote_port = self._parse_address(remote)
                
                # Extract PID/program
                pid = None
                program = None
                for part in parts:
                    if "/" in part:
                        pid_prog = part.split("/")
                        if pid_prog[0].isdigit():
                            pid = int(pid_prog[0])
                            program = pid_prog[1] if len(pid_prog) > 1 else None
                        break
                
                conn = NetworkConnection(
                    protocol=proto,
                    local_address=local_addr,
                    local_port=local_port,
                    remote_address=remote_addr,
                    remote_port=remote_port,
                    state=state,
                    pid=pid,
                    program=program,
                )
                connections.append(conn)
                
            except (ValueError, IndexError):
                continue
        
        return connections
    
    def _parse_address(self, addr_str: str) -> tuple[str, int]:
        """Parse address:port string."""
        if not addr_str or addr_str == "*:*":
            return ("*", 0)
        
        # Handle IPv6 [addr]:port
        if addr_str.startswith("["):
            match = re.match(r"\[([^\]]+)\]:(\d+)", addr_str)
            if match:
                return (match.group(1), int(match.group(2)))
        
        # Handle addr:port
        if ":" in addr_str:
            parts = addr_str.rsplit(":", 1)
            port = int(parts[1]) if parts[1].isdigit() else 0
            return (parts[0], port)
        
        return (addr_str, 0)
    
    def _parse_user_output(self, path: Path) -> list[UserInfo]:
        """Parse passwd/user files."""
        users = []
        
        with open(path, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # passwd format: user:x:uid:gid:gecos:home:shell
                parts = line.split(":")
                if len(parts) >= 7:
                    try:
                        user = UserInfo(
                            username=parts[0],
                            uid=int(parts[2]) if parts[2].isdigit() else 0,
                            gid=int(parts[3]) if parts[3].isdigit() else 0,
                            gecos=parts[4],
                            home=parts[5],
                            shell=parts[6],
                            is_system_user=int(parts[2]) < 1000 if parts[2].isdigit() else False,
                            has_valid_shell="/nologin" not in parts[6] and "/false" not in parts[6],
                        )
                        users.append(user)
                    except (ValueError, IndexError):
                        continue
        
        return users
    
    def _parse_hash_files(self) -> None:
        """Parse hash files."""
        if not self._extraction_result:
            return
        
        hash_entries = []
        
        for hash_path in self._extraction_result.hash_paths:
            path = Path(hash_path)
            if not path.exists() or path.is_dir():
                continue
            
            try:
                with open(path, "r", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Format: hash  filename (or hash|filename)
                        if "|" in line:
                            parts = line.split("|")
                        else:
                            parts = line.split(None, 1)
                        
                        if len(parts) >= 2:
                            hash_val = parts[0]
                            filepath = parts[1]
                            
                            # Determine hash type by length
                            entry = HashEntry(filepath=filepath)
                            if len(hash_val) == 32:
                                entry.md5 = hash_val
                            elif len(hash_val) == 40:
                                entry.sha1 = hash_val
                            elif len(hash_val) == 64:
                                entry.sha256 = hash_val
                            
                            hash_entries.append(entry)
                            
            except Exception as e:
                logger.warning(f"Failed to parse hash file {path}: {e}")
        
        self._parsed.hash_data = hash_entries
        logger.info(f"Parsed {len(hash_entries)} hash entries")
    
    def _parse_logs(self) -> None:
        """Parse log files (both plain text and UAC 3.x YAML format)."""
        if not self._extraction_result:
            return
        
        log_entries = []
        parsed_count = 0
        
        for log_path in self._extraction_result.log_paths:
            if parsed_count >= self.max_log_entries:
                break
            
            path = Path(log_path)
            if not path.exists() or path.is_dir():
                continue
            
            # Skip binary files
            if path.suffix.lower() in (".gz", ".bz2", ".xz", ".db", ".sqlite"):
                continue
            
            try:
                # Check if this is a YAML file (UAC 3.x format)
                if path.suffix.lower() in (".yaml", ".yml"):
                    entries = self._parse_yaml_log_file(path)
                    for entry in entries:
                        if parsed_count >= self.max_log_entries:
                            break
                        log_entries.append(entry)
                        parsed_count += 1
                else:
                    # Plain text log file
                    with open(path, "r", errors="ignore") as f:
                        for line in f:
                            if parsed_count >= self.max_log_entries:
                                break
                            
                            line = line.strip()
                            if not line:
                                continue
                            
                            entry = self._parse_log_line(line, str(path))
                            if entry:
                                log_entries.append(entry)
                                parsed_count += 1
                            
            except Exception as e:
                logger.debug(f"Failed to parse log {path}: {e}")
        
        self._parsed.logs = log_entries
        logger.info(f"Parsed {len(log_entries)} log entries")
    
    def _parse_yaml_log_file(self, path: Path) -> list[LogEntry]:
        """Parse UAC 3.x YAML format log file."""
        entries = []
        
        try:
            with open(path, "r", errors="ignore") as f:
                content = f.read()
            
            # UAC 3.x YAML may have multiple documents
            docs = list(yaml.safe_load_all(content))
            source_file = str(path)
            
            for doc in docs:
                if doc is None:
                    continue
                
                if isinstance(doc, dict):
                    # UAC 3.x wraps output in dict with 'output' key
                    output = doc.get("output", "")
                    
                    if isinstance(output, str):
                        # Raw log content stored as string - parse line by line
                        for line in output.split("\n"):
                            line = line.strip()
                            if line:
                                entry = self._parse_log_line(line, source_file)
                                if entry:
                                    entries.append(entry)
                    
                    elif isinstance(output, list):
                        # Structured log entries
                        for item in output:
                            if isinstance(item, dict):
                                entry = LogEntry(
                                    timestamp=None,
                                    source_file=source_file,
                                    raw_line=str(item),
                                    message=item.get("message", item.get("msg", str(item))),
                                    log_type="yaml",
                                    hostname=item.get("hostname", item.get("host")),
                                    pid=item.get("pid"),
                                )
                                # Try to parse timestamp
                                ts = item.get("timestamp", item.get("time", item.get("@timestamp")))
                                if ts:
                                    try:
                                        from dateutil import parser as date_parser
                                        entry.timestamp = date_parser.parse(str(ts))
                                    except Exception:
                                        pass
                                entries.append(entry)
                            elif isinstance(item, str) and item.strip():
                                entry = self._parse_log_line(item, source_file)
                                if entry:
                                    entries.append(entry)
                                    
                elif isinstance(doc, list):
                    # Direct list of entries
                    for item in doc:
                        if isinstance(item, str) and item.strip():
                            entry = self._parse_log_line(item, source_file)
                            if entry:
                                entries.append(entry)
                        elif isinstance(item, dict):
                            entry = LogEntry(
                                timestamp=None,
                                source_file=source_file,
                                raw_line=str(item),
                                message=item.get("message", item.get("msg", str(item))),
                                log_type="yaml",
                            )
                            entries.append(entry)
                            
                elif isinstance(doc, str):
                    # Plain string content
                    for line in doc.split("\n"):
                        line = line.strip()
                        if line:
                            entry = self._parse_log_line(line, source_file)
                            if entry:
                                entries.append(entry)
                                
        except Exception as e:
            logger.warning(f"Error parsing YAML log {path}: {e}")
        
        return entries
    
    def _parse_log_line(self, line: str, source_file: str) -> LogEntry | None:
        """Parse a single log line."""
        entry = LogEntry(
            timestamp=None,
            source_file=source_file,
            raw_line=line,
        )
        
        # Try common syslog format
        # Example: Dec  9 14:30:45 hostname process[pid]: message
        syslog_pattern = r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?\s*:\s*(.*)$"
        match = re.match(syslog_pattern, line)
        if match:
            try:
                timestamp_str = match.group(1)
                # Add current year for parsing
                year = datetime.now().year
                timestamp = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")
                
                entry.timestamp = timestamp
                entry.hostname = match.group(2)
                entry.parsed["process"] = match.group(3)
                if match.group(4):
                    entry.pid = int(match.group(4))
                entry.message = match.group(5)
                entry.log_type = "syslog"
                
                return entry
            except ValueError:
                pass
        
        # Try ISO format timestamps
        iso_pattern = r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)$"
        match = re.match(iso_pattern, line)
        if match:
            try:
                from dateutil import parser as date_parser
                entry.timestamp = date_parser.parse(match.group(1))
                entry.message = match.group(2)
                entry.log_type = "generic"
                return entry
            except Exception:
                pass
        
        # Fallback: store raw line
        entry.message = line
        entry.log_type = "unknown"
        return entry
    
    def _build_timeline(self) -> None:
        """Build timeline from all parsed artifacts."""
        timeline = []
        
        # Add bodyfile entries to timeline
        if self._parsed.bodyfile:
            for entry in self._parsed.bodyfile.entries:
                # Add modification time event
                if entry.mtime_dt:
                    event = TimelineEvent(
                        timestamp=entry.mtime_dt,
                        timestamp_desc="File Modified",
                        source="bodyfile",
                        source_type="filesystem",
                        message=f"File modified: {entry.name}",
                        artifact_path=entry.name,
                        extra_data={
                            "md5": entry.md5,
                            "size": entry.size,
                            "mode": entry.mode,
                        }
                    )
                    timeline.append(event)
                
                # Add creation time event if different
                if entry.crtime_dt and entry.crtime_dt != entry.mtime_dt:
                    event = TimelineEvent(
                        timestamp=entry.crtime_dt,
                        timestamp_desc="File Created",
                        source="bodyfile",
                        source_type="filesystem",
                        message=f"File created: {entry.name}",
                        artifact_path=entry.name,
                    )
                    timeline.append(event)
        
        # Add log entries to timeline
        for log_entry in self._parsed.logs:
            if log_entry.timestamp:
                event = TimelineEvent(
                    timestamp=log_entry.timestamp,
                    timestamp_desc="Log Entry",
                    source=Path(log_entry.source_file).name,
                    source_type="log",
                    message=log_entry.message or log_entry.raw_line[:200],
                    artifact_path=log_entry.source_file,
                    hostname=log_entry.hostname,
                    pid=log_entry.pid,
                )
                timeline.append(event)
        
        # Sort by timestamp
        timeline.sort(key=lambda e: e.timestamp)
        
        self._parsed.timeline = timeline
        logger.info(f"Built timeline with {len(timeline)} events")
    
    def _generate_structured_data(self) -> None:
        """Generate structured JSON for LLM consumption."""
        structured = {
            "metadata": {
                "hostname": self._parsed.hostname,
                "os_type": self._parsed.os_type,
                "collection_time": self._parsed.collection_time.isoformat() if self._parsed.collection_time else None,
            },
            "summary": {
                "total_files": self._parsed.bodyfile.total_entries if self._parsed.bodyfile else 0,
                "executable_files": len(self._parsed.bodyfile.executables) if self._parsed.bodyfile else 0,
                "setuid_files": len(self._parsed.bodyfile.setuid_files) if self._parsed.bodyfile else 0,
                "processes": len(self._parsed.live_response.processes) if self._parsed.live_response else 0,
                "network_connections": len(self._parsed.live_response.network_connections) if self._parsed.live_response else 0,
                "users": len(self._parsed.live_response.users) if self._parsed.live_response else 0,
                "hash_entries": len(self._parsed.hash_data),
                "log_entries": len(self._parsed.logs),
                "timeline_events": len(self._parsed.timeline),
            },
            "processes": [],
            "network": [],
            "users": [],
            "suspicious_files": [],
        }
        
        # Add process info (limited for token efficiency)
        if self._parsed.live_response:
            for proc in self._parsed.live_response.processes[:100]:
                structured["processes"].append({
                    "pid": proc.pid,
                    "ppid": proc.ppid,
                    "user": proc.user,
                    "command": proc.command[:200] if proc.command else "",
                    "cpu": proc.cpu,
                    "mem": proc.mem,
                })
            
            # Network connections
            for conn in self._parsed.live_response.network_connections[:100]:
                structured["network"].append({
                    "protocol": conn.protocol,
                    "local": f"{conn.local_address}:{conn.local_port}",
                    "remote": f"{conn.remote_address}:{conn.remote_port}" if conn.remote_address else None,
                    "state": conn.state,
                    "pid": conn.pid,
                    "program": conn.program,
                })
            
            # Users
            for user in self._parsed.live_response.users:
                structured["users"].append({
                    "username": user.username,
                    "uid": user.uid,
                    "shell": user.shell,
                    "home": user.home,
                    "is_system": user.is_system_user,
                    "has_valid_shell": user.has_valid_shell,
                })
        
        # Add suspicious files from bodyfile
        if self._parsed.bodyfile:
            # SUID files
            for entry in self._parsed.bodyfile.setuid_files[:50]:
                structured["suspicious_files"].append({
                    "type": "setuid",
                    "path": entry.name,
                    "mode": entry.mode,
                    "size": entry.size,
                })
            
            # Executables in unusual locations
            suspicious_paths = ["/tmp/", "/var/tmp/", "/dev/shm/"]
            for entry in self._parsed.bodyfile.executables[:200]:
                if any(p in entry.name for p in suspicious_paths):
                    structured["suspicious_files"].append({
                        "type": "executable_unusual_location",
                        "path": entry.name,
                        "mode": entry.mode,
                        "mtime": entry.mtime_dt.isoformat() if entry.mtime_dt else None,
                    })
        
        self._parsed.structured_data = structured
    
    def get_artifact_paths(self) -> dict[str, list[str]]:
        """Get categorized artifact paths."""
        if not self._extraction_result:
            return {}
        
        return {
            "bodyfile": [self._extraction_result.bodyfile_path] if self._extraction_result.bodyfile_path else [],
            "live_response": self._extraction_result.live_response_paths,
            "hash": self._extraction_result.hash_paths,
            "logs": self._extraction_result.log_paths,
            "config": self._extraction_result.config_paths,
        }
    
    def cleanup(self) -> None:
        """Clean up extracted files."""
        if self._extractor:
            self._extractor.cleanup()
    
    def __enter__(self) -> "UACParser":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.cleanup()
