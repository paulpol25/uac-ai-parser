#!/usr/bin/env python3
"""Quick test of UAC parsing with updated YAML support."""

import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

def test_parsing(archive_path: str):
    """Test parsing a UAC archive."""
    from uac_ai_parser.core.extractor import UACExtractor
    from uac_ai_parser.core.parser import UACParser
    
    print(f"\n=== Testing UAC parsing for: {archive_path} ===\n")
    
    # Extract
    extractor = UACExtractor(archive_path)
    print("Extracting archive...")
    result = extractor.extract()
    
    print(f"\nExtraction results:")
    print(f"  Total files: {result.total_files}")
    print(f"  Total size: {result.total_size / (1024*1024):.1f} MB")
    print(f"  Live response paths: {len(result.live_response_paths)}")
    print(f"  Log paths: {len(result.log_paths)}")
    print(f"  Hash paths: {len(result.hash_paths)}")
    print(f"  Config paths: {len(result.config_paths)}")
    print(f"  Bodyfile: {result.bodyfile_path}")
    
    # Show first 10 live response paths
    print(f"\n  First 10 live response paths:")
    for p in result.live_response_paths[:10]:
        print(f"    - {Path(p).name}")
    
    # Show first 10 log paths
    print(f"\n  First 10 log paths:")
    for p in result.log_paths[:10]:
        print(f"    - {Path(p).name}")
    
    # Parse
    print("\n\nParsing artifacts...")
    parser = UACParser(extractor)
    parsed = parser.parse()
    
    print(f"\nParsing results:")
    if parsed.live_response:
        print(f"  Processes: {len(parsed.live_response.processes)}")
        print(f"  Network connections: {len(parsed.live_response.network_connections)}")
        print(f"  Users: {len(parsed.live_response.users)}")
        print(f"  Raw outputs: {len(parsed.live_response.raw_outputs)}")
        
        # Show first 5 processes
        if parsed.live_response.processes:
            print(f"\n  First 5 processes:")
            for p in parsed.live_response.processes[:5]:
                print(f"    - PID={p.pid}, USER={p.user}, CMD={p.command[:50] if p.command else 'N/A'}...")
    
    print(f"  Log entries: {len(parsed.logs)}")
    
    # Show first 5 log entries
    if parsed.logs:
        print(f"\n  First 5 log entries:")
        for entry in parsed.logs[:5]:
            msg = entry.message[:60] if entry.message else entry.raw_line[:60]
            print(f"    - {entry.timestamp or 'NO_TS'}: {msg}...")
    
    if parsed.bodyfile:
        print(f"  Bodyfile entries: {len(parsed.bodyfile.entries)}")
    
    if parsed.timeline:
        print(f"  Timeline events: {len(parsed.timeline.events)}")
    
    print("\n=== Test complete ===\n")
    return parsed


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_parsing.py <archive_path>")
        print("\nExample: python test_parsing.py /path/to/uac-collection.tar.gz")
        sys.exit(1)
    
    test_parsing(sys.argv[1])
