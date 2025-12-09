"""
Plaso integration for super timeline generation.

Provides Docker-based Plaso execution for generating
comprehensive forensic timelines from UAC outputs.
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PlasoIntegration:
    """
    Plaso integration for super timeline generation.
    
    Uses Docker to run Plaso's log2timeline and psort
    for comprehensive timeline analysis.
    
    Example:
        ```python
        plaso = PlasoIntegration()
        
        # Check if available
        if plaso.is_available():
            # Generate timeline
            csv_path = plaso.generate_timeline(
                "/path/to/uac-output.tar.gz",
                "/output/dir",
            )
        ```
    """
    
    def __init__(
        self,
        docker_image: str = "log2timeline/plaso:latest",
        timeout: int = 3600,
    ):
        """
        Initialize Plaso integration.
        
        Args:
            docker_image: Plaso Docker image to use
            timeout: Timeout for Plaso operations in seconds
        """
        self.docker_image = docker_image
        self.timeout = timeout
    
    def is_available(self) -> bool:
        """Check if Docker and Plaso image are available."""
        try:
            # Check Docker
            result = subprocess.run(
                ["docker", "version"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.warning("Docker not available")
                return False
            
            # Check if image exists (don't pull automatically)
            result = subprocess.run(
                ["docker", "images", "-q", self.docker_image],
                capture_output=True,
                timeout=10,
            )
            
            if not result.stdout.strip():
                logger.info(f"Plaso image not found: {self.docker_image}")
                return False
            
            return True
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"Docker check failed: {e}")
            return False
    
    def pull_image(self) -> bool:
        """Pull the Plaso Docker image."""
        logger.info(f"Pulling Plaso image: {self.docker_image}")
        
        try:
            result = subprocess.run(
                ["docker", "pull", self.docker_image],
                capture_output=True,
                timeout=600,  # 10 minutes for download
            )
            return result.returncode == 0
            
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.error(f"Failed to pull Plaso image: {e}")
            return False
    
    def generate_timeline(
        self,
        uac_archive: str | Path,
        output_dir: str | Path,
        output_format: str = "l2tcsv",
    ) -> Path | None:
        """
        Generate a super timeline from UAC output.
        
        Args:
            uac_archive: Path to UAC tar.gz/zip file
            output_dir: Directory for output files
            output_format: Output format (l2tcsv, json_line, etc.)
            
        Returns:
            Path to generated timeline CSV or None on failure
        """
        uac_archive = Path(uac_archive).resolve()
        output_dir = Path(output_dir).resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        
        archive_name = uac_archive.stem.replace(".tar", "")
        plaso_file = output_dir / f"{archive_name}.plaso"
        timeline_file = output_dir / f"{archive_name}.csv"
        
        logger.info(f"Generating timeline for: {uac_archive}")
        
        # Step 1: Run log2timeline
        if not self._run_log2timeline(uac_archive, plaso_file):
            return None
        
        # Step 2: Run psort
        if not self._run_psort(plaso_file, timeline_file, output_format):
            return None
        
        logger.info(f"Timeline generated: {timeline_file}")
        return timeline_file
    
    def _run_log2timeline(
        self,
        input_file: Path,
        output_file: Path,
    ) -> bool:
        """Run log2timeline to create .plaso file."""
        logger.info("Running log2timeline...")
        
        # Mount directories
        input_dir = input_file.parent
        output_dir = output_file.parent
        
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{input_dir}:/input:ro",
            "-v", f"{output_dir}:/output",
            self.docker_image,
            "log2timeline",
            "--storage-file", f"/output/{output_file.name}",
            f"/input/{input_file.name}",
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
            )
            
            if result.returncode != 0:
                logger.error(f"log2timeline failed: {result.stderr.decode()}")
                return False
            
            return output_file.exists()
            
        except subprocess.TimeoutExpired:
            logger.error("log2timeline timed out")
            return False
        except Exception as e:
            logger.error(f"log2timeline error: {e}")
            return False
    
    def _run_psort(
        self,
        plaso_file: Path,
        output_file: Path,
        output_format: str = "l2tcsv",
    ) -> bool:
        """Run psort to generate timeline."""
        logger.info("Running psort...")
        
        plaso_dir = plaso_file.parent
        
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{plaso_dir}:/data",
            self.docker_image,
            "psort.py",
            "-o", output_format,
            f"/data/{plaso_file.name}",
            "-w", f"/data/{output_file.name}",
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
            )
            
            if result.returncode != 0:
                logger.error(f"psort failed: {result.stderr.decode()}")
                return False
            
            return output_file.exists()
            
        except subprocess.TimeoutExpired:
            logger.error("psort timed out")
            return False
        except Exception as e:
            logger.error(f"psort error: {e}")
            return False
    
    def parse_l2tcsv(self, csv_path: str | Path) -> list[dict[str, Any]]:
        """
        Parse L2T CSV timeline into list of events.
        
        Args:
            csv_path: Path to L2T CSV file
            
        Returns:
            List of timeline event dictionaries
        """
        import csv
        from datetime import datetime
        
        events = []
        
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                try:
                    # L2T CSV columns
                    event = {
                        "date": row.get("date", ""),
                        "time": row.get("time", ""),
                        "timezone": row.get("timezone", "UTC"),
                        "macb": row.get("MACB", ""),
                        "source": row.get("source", ""),
                        "sourcetype": row.get("sourcetype", ""),
                        "type": row.get("type", ""),
                        "user": row.get("user", ""),
                        "host": row.get("host", ""),
                        "short": row.get("short", ""),
                        "desc": row.get("desc", ""),
                        "version": row.get("version", ""),
                        "filename": row.get("filename", ""),
                        "inode": row.get("inode", ""),
                        "notes": row.get("notes", ""),
                        "format": row.get("format", ""),
                        "extra": row.get("extra", ""),
                    }
                    
                    # Parse timestamp
                    if event["date"] and event["time"]:
                        try:
                            dt_str = f"{event['date']} {event['time']}"
                            event["timestamp"] = datetime.strptime(
                                dt_str, "%m/%d/%Y %H:%M:%S"
                            )
                        except ValueError:
                            event["timestamp"] = None
                    
                    events.append(event)
                    
                except Exception:
                    continue
        
        return events
