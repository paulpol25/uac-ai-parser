"""
UAC Archive Extractor.

Handles extraction of UAC output archives (tar.gz, zip) while respecting
the directory structure and volatility order of artifacts.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Generator, Iterator

logger = logging.getLogger(__name__)


@dataclass
class ExtractedArtifact:
    """Represents an extracted artifact file."""
    
    relative_path: str
    absolute_path: str
    size: int
    is_directory: bool
    category: str = "unknown"
    
    @property
    def filename(self) -> str:
        """Get just the filename."""
        return Path(self.relative_path).name
    
    @property
    def parent_dir(self) -> str:
        """Get the parent directory path."""
        return str(Path(self.relative_path).parent)


@dataclass
class ExtractionResult:
    """Result of UAC archive extraction."""
    
    source_file: str
    extract_dir: str
    artifacts: list[ExtractedArtifact] = field(default_factory=list)
    
    # Categorized artifact paths
    bodyfile_path: str | None = None
    live_response_paths: list[str] = field(default_factory=list)
    hash_paths: list[str] = field(default_factory=list)
    log_paths: list[str] = field(default_factory=list)
    config_paths: list[str] = field(default_factory=list)
    
    # Metadata from UAC
    uac_log_path: str | None = None
    hostname: str | None = None
    os_type: str | None = None
    collection_time: str | None = None
    
    @property
    def total_files(self) -> int:
        """Total number of extracted files."""
        return len([a for a in self.artifacts if not a.is_directory])
    
    @property
    def total_size(self) -> int:
        """Total size of extracted files in bytes."""
        return sum(a.size for a in self.artifacts if not a.is_directory)


class UACExtractor:
    """
    Extract and organize UAC output archives.
    
    Handles both tar.gz and zip formats, categorizing artifacts
    for downstream processing.
    """
    
    # Artifact category patterns - expanded for different UAC versions (2.x and 3.x)
    # UAC 3.x uses YAML files with structured output
    CATEGORY_PATTERNS = {
        "bodyfile": ["bodyfile.txt", "bodyfile/", "/bodyfile", "bodyfile.yaml"],
        "live_response": [
            "live_response/", "/live_response", 
            "process/", "/process",
            "network/", "/network",
            "system/", "/system",
            "user/", "/user",
            "hardware/", "/hardware",
            "software/", "/software",
            "disk/", "/disk",
            "memory/", "/memory",
            "storage/", "/storage",
            "containers/", "/containers",
            "vms/", "/vms",
            "packages/", "/packages",
        ],
        "hash": [
            "hash_executables/", "hash_running_processes/", 
            "_hash.txt", ".md5", ".sha1", ".sha256",
            "/hash/", "hashes/",
            "hash_executables.yaml", "hash_running_processes.yaml",
        ],
        "logs": [
            "/var/log/", "/var/adm/", 
            "logs/", "/logs",
            "files/logs/",
            ".log", "_log",
            "syslog", "messages", "auth", "secure", "audit",
            "dmesg", "journal",
            "var_log.yaml", "var_adm.yaml", "journal.yaml",
            "apache.yaml", "nginx.yaml", "tomcat.yaml",
        ],
        "config": [
            "/etc/", "config/", "/config",
            ".conf", ".cfg", ".yaml", ".yml", ".ini",
            "crontab", "sudoers", "passwd", "shadow", "group",
            "files/system/etc.yaml",
        ],
        "system": [
            "system/", "/system",
            "uname", "hostname", "os-release", 
            "uptime", "date", "mount",
            "chkrootkit/",
            "files/system/",
        ],
        "files": [
            "files/", "/files",
            "files/applications/",
            "files/shell/",
            "files/ssh/",
        ],
    }
    
    def __init__(
        self,
        archive_path: str | Path,
        extract_dir: str | Path | None = None,
        cleanup_on_error: bool = True,
    ):
        """
        Initialize the extractor.
        
        Args:
            archive_path: Path to the UAC output archive
            extract_dir: Directory to extract to (temp dir if None)
            cleanup_on_error: Whether to clean up on extraction error
        """
        self.archive_path = Path(archive_path)
        self._validate_archive()
        
        if extract_dir:
            self.extract_dir = Path(extract_dir)
            self.extract_dir.mkdir(parents=True, exist_ok=True)
            self._temp_dir = None
        else:
            self._temp_dir = tempfile.mkdtemp(prefix="uac_ai_")
            self.extract_dir = Path(self._temp_dir)
        
        self.cleanup_on_error = cleanup_on_error
        self._extracted = False
    
    def _validate_archive(self) -> None:
        """Validate the archive file exists and is supported."""
        if not self.archive_path.exists():
            raise FileNotFoundError(f"Archive not found: {self.archive_path}")
        
        suffix = self.archive_path.suffix.lower()
        suffixes = "".join(self.archive_path.suffixes).lower()
        
        if suffixes not in (".tar.gz", ".tgz", ".tar", ".zip"):
            if suffix not in (".gz", ".tar", ".zip"):
                raise ValueError(
                    f"Unsupported archive format: {suffix}. "
                    "Expected .tar.gz, .tgz, .tar, or .zip"
                )
    
    @property
    def is_tarball(self) -> bool:
        """Check if archive is a tar/tar.gz file."""
        suffixes = "".join(self.archive_path.suffixes).lower()
        return suffixes in (".tar.gz", ".tgz", ".tar") or self.archive_path.suffix.lower() == ".tar"
    
    @property
    def is_zipfile(self) -> bool:
        """Check if archive is a zip file."""
        return self.archive_path.suffix.lower() == ".zip"
    
    def extract(self) -> ExtractionResult:
        """
        Extract the UAC archive.
        
        Returns:
            ExtractionResult with categorized artifact paths
        """
        logger.info(f"Extracting UAC archive: {self.archive_path}")
        
        try:
            if self.is_tarball:
                artifacts = self._extract_tar()
            elif self.is_zipfile:
                artifacts = self._extract_zip()
            else:
                # Try to detect format
                artifacts = self._extract_auto()
            
            result = self._categorize_artifacts(artifacts)
            self._extracted = True
            
            logger.info(
                f"Extracted {result.total_files} files "
                f"({result.total_size / 1024 / 1024:.2f} MB)"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            if self.cleanup_on_error and self._temp_dir:
                self.cleanup()
            raise
    
    def _extract_tar(self) -> list[ExtractedArtifact]:
        """Extract tar/tar.gz archive."""
        # Try Python's tarfile first, fall back to system tar if it fails
        try:
            return self._extract_tar_python()
        except Exception as e:
            # Check if files were partially extracted despite the error
            extracted_files = list(self.extract_dir.rglob("*"))
            if extracted_files:
                logger.warning(f"Python tarfile had error ({e}), but files were extracted. Continuing...")
                return self._scan_extracted_files()
            
            logger.warning(f"Python tarfile failed ({e}), trying system tar...")
            return self._extract_tar_system()
    
    def _scan_extracted_files(self) -> list[ExtractedArtifact]:
        """Scan extract directory and build artifact list from existing files."""
        artifacts = []
        for item in self.extract_dir.rglob("*"):
            rel_path = item.relative_to(self.extract_dir)
            try:
                size = item.stat().st_size if item.is_file() else 0
            except OSError:
                size = 0
            artifacts.append(ExtractedArtifact(
                relative_path=str(rel_path),
                absolute_path=str(item),
                size=size,
                is_directory=item.is_dir(),
            ))
        return artifacts
    
    def _extract_tar_python(self) -> list[ExtractedArtifact]:
        """Extract tar/tar.gz archive using Python's tarfile."""
        artifacts = []
        
        mode = "r:gz" if self.archive_path.suffix.lower() in (".gz", ".tgz") else "r"
        if "".join(self.archive_path.suffixes).lower() == ".tar.gz":
            mode = "r:gz"
        
        with tarfile.open(self.archive_path, mode) as tar:
            # Security: prevent path traversal
            for member in tar.getmembers():
                if member.name.startswith("/") or ".." in member.name:
                    logger.warning(f"Skipping suspicious path: {member.name}")
                    continue
                
                try:
                    tar.extract(member, self.extract_dir)
                    
                    extracted_path = self.extract_dir / member.name
                    artifacts.append(ExtractedArtifact(
                        relative_path=member.name,
                        absolute_path=str(extracted_path),
                        size=member.size,
                        is_directory=member.isdir(),
                    ))
                except Exception as e:
                    logger.warning(f"Failed to extract {member.name}: {e}")
        
        return artifacts
    
    def _extract_tar_system(self) -> list[ExtractedArtifact]:
        """Extract tar/tar.gz archive using system tar command."""
        import subprocess
        
        # Use system tar which is more forgiving with certain archive formats
        cmd = ["tar", "-xf", str(self.archive_path), "-C", str(self.extract_dir)]
        
        logger.debug(f"Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        # Check if files were extracted, even if tar reported an error
        # (truncated archives often extract successfully but report EOF error)
        extracted_files = list(self.extract_dir.rglob("*"))
        logger.debug(f"Found {len(extracted_files)} items after extraction")
        
        if result.returncode != 0:
            if extracted_files:
                logger.warning(
                    f"System tar reported error but {len(extracted_files)} files were extracted"
                )
            else:
                raise RuntimeError(f"System tar failed: {result.stderr}")
        
        # Walk the extracted directory to build artifact list
        artifacts = []
        file_count = 0
        dir_count = 0
        
        for root, dirs, files in os.walk(self.extract_dir):
            root_path = Path(root)
            
            # Add directories
            for d in dirs:
                dir_path = root_path / d
                rel_path = dir_path.relative_to(self.extract_dir)
                artifacts.append(ExtractedArtifact(
                    relative_path=str(rel_path),
                    absolute_path=str(dir_path),
                    size=0,
                    is_directory=True,
                ))
                dir_count += 1
            
            # Add files
            for f in files:
                file_path = root_path / f
                rel_path = file_path.relative_to(self.extract_dir)
                try:
                    size = file_path.stat().st_size
                except OSError:
                    size = 0
                artifacts.append(ExtractedArtifact(
                    relative_path=str(rel_path),
                    absolute_path=str(file_path),
                    size=size,
                    is_directory=False,
                ))
                file_count += 1
        
        logger.debug(f"Built artifact list: {file_count} files, {dir_count} directories")
        return artifacts
    
    def _extract_zip(self) -> list[ExtractedArtifact]:
        """Extract zip archive."""
        artifacts = []
        
        with zipfile.ZipFile(self.archive_path, "r") as zf:
            for info in zf.infolist():
                # Security: prevent path traversal
                if info.filename.startswith("/") or ".." in info.filename:
                    logger.warning(f"Skipping suspicious path: {info.filename}")
                    continue
                
                try:
                    zf.extract(info, self.extract_dir)
                    
                    extracted_path = self.extract_dir / info.filename
                    artifacts.append(ExtractedArtifact(
                        relative_path=info.filename,
                        absolute_path=str(extracted_path),
                        size=info.file_size,
                        is_directory=info.is_dir(),
                    ))
                except Exception as e:
                    logger.warning(f"Failed to extract {info.filename}: {e}")
        
        return artifacts
    
    def _extract_auto(self) -> list[ExtractedArtifact]:
        """Try to auto-detect and extract archive format."""
        # Try tar.gz first
        try:
            with tarfile.open(self.archive_path, "r:*") as tar:
                pass  # Just testing if it opens
            return self._extract_tar()
        except tarfile.TarError:
            pass
        
        # Try zip
        try:
            with zipfile.ZipFile(self.archive_path, "r") as zf:
                pass  # Just testing if it opens
            return self._extract_zip()
        except zipfile.BadZipFile:
            pass
        
        raise ValueError(f"Could not determine archive format: {self.archive_path}")
    
    def _categorize_artifacts(
        self, 
        artifacts: list[ExtractedArtifact]
    ) -> ExtractionResult:
        """Categorize extracted artifacts by type."""
        result = ExtractionResult(
            source_file=str(self.archive_path),
            extract_dir=str(self.extract_dir),
        )
        
        logger.debug(f"Categorizing {len(artifacts)} artifacts")
        categorized_counts = {"bodyfile": 0, "live_response": 0, "hash": 0, "logs": 0, "config": 0, "other": 0}
        
        for artifact in artifacts:
            # Categorize based on path patterns
            path_lower = artifact.relative_path.lower()
            is_yaml = path_lower.endswith(".yaml") or path_lower.endswith(".yml")
            
            # Log the first 20 artifacts for debugging
            if sum(categorized_counts.values()) < 20:
                logger.debug(f"Categorizing: {artifact.relative_path} (dir={artifact.is_directory})")
            
            # Bodyfile
            if "bodyfile.txt" in path_lower or path_lower.endswith("/bodyfile.txt") or "bodyfile.yaml" in path_lower:
                result.bodyfile_path = artifact.absolute_path
                artifact.category = "bodyfile"
                categorized_counts["bodyfile"] += 1
                logger.debug(f"Found bodyfile: {artifact.relative_path}")
            
            # Live response - check multiple patterns
            # In UAC 3.x, most data is in YAML files under live_response/ or similar
            elif any(p in path_lower for p in self.CATEGORY_PATTERNS["live_response"]):
                if not artifact.is_directory:
                    result.live_response_paths.append(artifact.absolute_path)
                    categorized_counts["live_response"] += 1
                artifact.category = "live_response"
            
            # Hash files
            elif any(p in path_lower for p in self.CATEGORY_PATTERNS["hash"]):
                if not artifact.is_directory:
                    result.hash_paths.append(artifact.absolute_path)
                    categorized_counts["hash"] += 1
                artifact.category = "hash"
            
            # Log files - include files/ directory with log content (UAC 3.x)
            elif any(p in path_lower for p in self.CATEGORY_PATTERNS["logs"]):
                if not artifact.is_directory:
                    result.log_paths.append(artifact.absolute_path)
                    categorized_counts["logs"] += 1
                artifact.category = "logs"
            
            # Files directory (UAC 3.x) - treat as logs/live_response
            elif "files/" in path_lower and is_yaml:
                if not artifact.is_directory:
                    # Check if it's log-related
                    if any(x in path_lower for x in ["log", "journal", "syslog", "messages", "auth", "secure"]):
                        result.log_paths.append(artifact.absolute_path)
                        categorized_counts["logs"] += 1
                        artifact.category = "logs"
                    else:
                        # Treat as live response data
                        result.live_response_paths.append(artifact.absolute_path)
                        categorized_counts["live_response"] += 1
                        artifact.category = "live_response"
            
            # Config files
            elif any(p in path_lower for p in self.CATEGORY_PATTERNS["config"]):
                if not artifact.is_directory:
                    result.config_paths.append(artifact.absolute_path)
                    categorized_counts["config"] += 1
                artifact.category = "config"
            
            # Generic YAML files that haven't been categorized yet - likely live response
            elif is_yaml and not artifact.is_directory and artifact.category is None:
                result.live_response_paths.append(artifact.absolute_path)
                categorized_counts["live_response"] += 1
                artifact.category = "live_response"
            
            else:
                categorized_counts["other"] += 1
            
            # UAC log
            if "uac.log" in path_lower:
                result.uac_log_path = artifact.absolute_path
            
            result.artifacts.append(artifact)
        
        # Log summary of categorization
        logger.info(
            f"Categorization summary: "
            f"bodyfile={categorized_counts['bodyfile']}, "
            f"live_response={categorized_counts['live_response']}, "
            f"hash={categorized_counts['hash']}, "
            f"logs={categorized_counts['logs']}, "
            f"config={categorized_counts['config']}, "
            f"other={categorized_counts['other']}"
        )
        
        # Try to extract metadata from UAC log or directory structure
        self._extract_metadata(result)
        
        return result
    
    def _extract_metadata(self, result: ExtractionResult) -> None:
        """Extract UAC collection metadata."""
        # Try to parse hostname from directory structure
        # UAC creates: uac-<hostname>-<os>-<timestamp>/
        for artifact in result.artifacts:
            if artifact.is_directory and artifact.relative_path.startswith("uac-"):
                parts = artifact.relative_path.split("-")
                if len(parts) >= 3:
                    result.hostname = parts[1]
                    result.os_type = parts[2] if len(parts) > 2 else None
                    if len(parts) > 3:
                        result.collection_time = parts[-1].rstrip("/")
                break
        
        # Parse UAC log if available
        if result.uac_log_path and Path(result.uac_log_path).exists():
            try:
                with open(result.uac_log_path, "r", errors="ignore") as f:
                    for line in f:
                        if "hostname:" in line.lower():
                            result.hostname = line.split(":", 1)[-1].strip()
                        elif "os:" in line.lower() or "system:" in line.lower():
                            result.os_type = line.split(":", 1)[-1].strip()
            except Exception as e:
                logger.debug(f"Could not parse UAC log: {e}")
    
    def iter_files(
        self, 
        category: str | None = None,
        pattern: str | None = None,
    ) -> Generator[ExtractedArtifact, None, None]:
        """
        Iterate over extracted files.
        
        Args:
            category: Filter by category (bodyfile, live_response, hash, logs, config)
            pattern: Glob pattern to match filenames
        """
        if not self._extracted:
            raise RuntimeError("Archive not yet extracted. Call extract() first.")
        
        import fnmatch
        
        for artifact in self.extract_dir.rglob("*"):
            if artifact.is_file():
                rel_path = str(artifact.relative_to(self.extract_dir))
                
                if category:
                    # Check if matches category
                    path_lower = rel_path.lower()
                    if category == "bodyfile" and "bodyfile.txt" not in path_lower:
                        continue
                    elif category == "live_response":
                        if not any(p in path_lower for p in self.CATEGORY_PATTERNS["live_response"]):
                            continue
                    # Add other category checks as needed
                
                if pattern and not fnmatch.fnmatch(artifact.name, pattern):
                    continue
                
                yield ExtractedArtifact(
                    relative_path=rel_path,
                    absolute_path=str(artifact),
                    size=artifact.stat().st_size,
                    is_directory=False,
                )
    
    def read_file(self, relative_path: str) -> str:
        """Read contents of an extracted file."""
        file_path = self.extract_dir / relative_path
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {relative_path}")
        
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    
    def read_file_lines(
        self, 
        relative_path: str, 
        max_lines: int | None = None
    ) -> Iterator[str]:
        """Read file line by line."""
        file_path = self.extract_dir / relative_path
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {relative_path}")
        
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for i, line in enumerate(f):
                if max_lines and i >= max_lines:
                    break
                yield line.rstrip("\n\r")
    
    def cleanup(self) -> None:
        """Clean up temporary extraction directory."""
        if self._temp_dir and Path(self._temp_dir).exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
            logger.debug(f"Cleaned up temp directory: {self._temp_dir}")
            self._temp_dir = None
    
    def __enter__(self) -> "UACExtractor":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with cleanup."""
        self.cleanup()


def extract_uac_archive(
    archive_path: str | Path,
    output_dir: str | Path | None = None,
) -> ExtractionResult:
    """
    Convenience function to extract a UAC archive.
    
    Args:
        archive_path: Path to UAC output archive
        output_dir: Directory to extract to (creates temp if None)
    
    Returns:
        ExtractionResult with categorized artifact paths
    """
    extractor = UACExtractor(archive_path, output_dir)
    return extractor.extract()
