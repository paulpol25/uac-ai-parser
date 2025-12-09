"""
Tests for UAC parser and extractor.
"""

import pytest
import tempfile
import tarfile
import os
from pathlib import Path

from uac_ai_parser.core.extractor import UACExtractor, ExtractionResult


class TestUACExtractor:
    """Tests for UAC archive extraction."""
    
    @pytest.fixture
    def sample_tarball(self, tmp_path):
        """Create a sample UAC-like tarball for testing."""
        # Create directory structure
        uac_dir = tmp_path / "uac-testhost-linux-20231209120000"
        uac_dir.mkdir()
        
        # Create live_response directory
        live_response = uac_dir / "live_response" / "process"
        live_response.mkdir(parents=True)
        
        # Create sample ps output
        ps_file = live_response / "ps_auxwww.txt"
        ps_file.write_text("""USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168936 11788 ?        Ss   Dec08   0:02 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Dec08   0:00 [kthreadd]
www-data  1234  0.5  2.0 512000 40000 ?        S    Dec08   1:00 /usr/sbin/apache2
""")
        
        # Create bodyfile
        bodyfile_dir = uac_dir / "bodyfile"
        bodyfile_dir.mkdir()
        bodyfile = bodyfile_dir / "bodyfile.txt"
        bodyfile.write_text("""0|/usr/bin/bash|12345|-rwxr-xr-x|0|0|1234567|1702100000|1702100000|1702100000|1702100000
0|/tmp/suspicious.sh|99999|-rwxr-xr-x|1000|1000|500|1702150000|1702150000|1702150000|1702150000
d41d8cd98f00b204e9800998ecf8427e|/usr/bin/sudo|11111|-rwsr-xr-x|0|0|200000|1700000000|1700000000|1700000000|1700000000
""")
        
        # Create UAC log
        uac_log = uac_dir / "uac.log"
        uac_log.write_text("UAC version: 2.0\nhostname: testhost\n")
        
        # Create tarball
        tarball_path = tmp_path / "uac-testhost-linux-20231209120000.tar.gz"
        with tarfile.open(tarball_path, "w:gz") as tar:
            tar.add(uac_dir, arcname=uac_dir.name)
        
        return tarball_path
    
    def test_extract_tarball(self, sample_tarball, tmp_path):
        """Test basic tarball extraction."""
        extract_dir = tmp_path / "extracted"
        
        extractor = UACExtractor(sample_tarball, extract_dir)
        result = extractor.extract()
        
        assert result.total_files > 0
        assert result.bodyfile_path is not None
        assert Path(result.bodyfile_path).exists()
    
    def test_categorize_artifacts(self, sample_tarball, tmp_path):
        """Test artifact categorization."""
        extract_dir = tmp_path / "extracted"
        
        extractor = UACExtractor(sample_tarball, extract_dir)
        result = extractor.extract()
        
        assert result.bodyfile_path is not None
        assert len(result.live_response_paths) > 0
    
    def test_extract_metadata(self, sample_tarball, tmp_path):
        """Test metadata extraction from archive."""
        extract_dir = tmp_path / "extracted"
        
        extractor = UACExtractor(sample_tarball, extract_dir)
        result = extractor.extract()
        
        assert result.hostname == "testhost"
    
    def test_cleanup(self, sample_tarball):
        """Test temp directory cleanup."""
        extractor = UACExtractor(sample_tarball)
        result = extractor.extract()
        
        extract_dir = result.extract_dir
        assert Path(extract_dir).exists()
        
        extractor.cleanup()
        # After cleanup, temp dir should be removed
    
    def test_context_manager(self, sample_tarball, tmp_path):
        """Test using extractor as context manager."""
        extract_dir = tmp_path / "extracted"
        
        with UACExtractor(sample_tarball, extract_dir) as extractor:
            result = extractor.extract()
            assert result.total_files > 0
    
    def test_invalid_archive(self, tmp_path):
        """Test handling of invalid archive."""
        invalid_file = tmp_path / "invalid.tar.gz"
        invalid_file.write_text("not a tarball")
        
        with pytest.raises(Exception):
            extractor = UACExtractor(invalid_file)
            extractor.extract()
    
    def test_nonexistent_file(self, tmp_path):
        """Test handling of nonexistent file."""
        with pytest.raises(FileNotFoundError):
            UACExtractor(tmp_path / "nonexistent.tar.gz")


class TestExtractionResult:
    """Tests for ExtractionResult dataclass."""
    
    def test_total_files_count(self):
        """Test file counting."""
        from uac_ai_parser.core.extractor import ExtractedArtifact
        
        result = ExtractionResult(
            source_file="/test.tar.gz",
            extract_dir="/tmp/test",
            artifacts=[
                ExtractedArtifact("/file1", "/tmp/test/file1", 100, False),
                ExtractedArtifact("/file2", "/tmp/test/file2", 200, False),
                ExtractedArtifact("/dir1", "/tmp/test/dir1", 0, True),
            ]
        )
        
        assert result.total_files == 2  # Excludes directories
    
    def test_total_size(self):
        """Test size calculation."""
        from uac_ai_parser.core.extractor import ExtractedArtifact
        
        result = ExtractionResult(
            source_file="/test.tar.gz",
            extract_dir="/tmp/test",
            artifacts=[
                ExtractedArtifact("/file1", "/tmp/test/file1", 100, False),
                ExtractedArtifact("/file2", "/tmp/test/file2", 200, False),
            ]
        )
        
        assert result.total_size == 300
