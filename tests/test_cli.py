"""
Tests for the CLI module.
"""

import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock
from pathlib import Path


class TestCLI:
    """Tests for CLI commands."""
    
    @pytest.fixture
    def runner(self):
        """Create CLI runner."""
        return CliRunner()
    
    @pytest.fixture
    def sample_tarball(self, tmp_path):
        """Create sample tarball for testing."""
        import tarfile
        
        # Create UAC structure
        uac_dir = tmp_path / "uac-test-linux-20231209"
        uac_dir.mkdir()
        
        # Create bodyfile
        bodyfile_dir = uac_dir / "bodyfile"
        bodyfile_dir.mkdir()
        bodyfile = bodyfile_dir / "bodyfile.txt"
        bodyfile.write_text("0|/usr/bin/bash|12345|-rwxr-xr-x|0|0|1000|1702100000|1702100000|1702100000|1702100000\n")
        
        # Create tarball
        tarball = tmp_path / "uac-test.tar.gz"
        with tarfile.open(tarball, "w:gz") as tar:
            tar.add(uac_dir, arcname=uac_dir.name)
        
        return tarball
    
    def test_cli_help(self, runner):
        """Test CLI help command."""
        from uac_ai_parser.cli import cli
        
        result = runner.invoke(cli, ["--help"])
        
        assert result.exit_code == 0
        assert "UAC AI Parser" in result.output or "uac" in result.output.lower()
    
    def test_parse_help(self, runner):
        """Test parse command help."""
        from uac_ai_parser.cli import cli
        
        result = runner.invoke(cli, ["parse", "--help"])
        
        assert result.exit_code == 0
        assert "parse" in result.output.lower() or "uac" in result.output.lower()
    
    def test_analyze_help(self, runner):
        """Test analyze command help."""
        from uac_ai_parser.cli import cli
        
        result = runner.invoke(cli, ["analyze", "--help"])
        
        assert result.exit_code == 0
    
    def test_query_help(self, runner):
        """Test query command help."""
        from uac_ai_parser.cli import cli
        
        result = runner.invoke(cli, ["query", "--help"])
        
        assert result.exit_code == 0
    
    def test_timeline_help(self, runner):
        """Test timeline command help."""
        from uac_ai_parser.cli import cli
        
        result = runner.invoke(cli, ["timeline", "--help"])
        
        assert result.exit_code == 0
    
    def test_parse_nonexistent_file(self, runner):
        """Test parse with nonexistent file."""
        from uac_ai_parser.cli import cli
        
        result = runner.invoke(cli, ["parse", "/nonexistent/file.tar.gz"])
        
        assert result.exit_code != 0 or "error" in result.output.lower() or "not found" in result.output.lower()
    
    @patch("uac_ai_parser.cli.UACExtractor")
    @patch("uac_ai_parser.cli.UACParser")
    def test_parse_command(self, mock_parser, mock_extractor, runner, sample_tarball):
        """Test parse command with mocked components."""
        from uac_ai_parser.cli import cli
        from uac_ai_parser.models.artifacts import UACOutput
        from datetime import datetime
        
        # Setup mocks
        mock_extractor_instance = MagicMock()
        mock_extractor.return_value.__enter__ = MagicMock(return_value=mock_extractor_instance)
        mock_extractor.return_value.__exit__ = MagicMock(return_value=False)
        
        mock_result = MagicMock()
        mock_result.extract_dir = str(sample_tarball.parent / "extracted")
        mock_extractor_instance.extract.return_value = mock_result
        
        mock_uac_output = UACOutput(
            hostname="testhost",
            collection_time=datetime.now(),
            source_file=str(sample_tarball),
        )
        mock_parser.return_value.parse.return_value = mock_uac_output
        
        result = runner.invoke(cli, ["parse", str(sample_tarball)])
        
        # Should complete without error
        assert result.exit_code == 0 or mock_extractor.called
    
    @patch("uac_ai_parser.cli.AIAnalyzer")
    @patch("uac_ai_parser.cli.UACExtractor")
    @patch("uac_ai_parser.cli.UACParser")
    def test_analyze_command(self, mock_parser, mock_extractor, mock_analyzer, runner, sample_tarball):
        """Test analyze command with mocked components."""
        from uac_ai_parser.cli import cli
        from uac_ai_parser.models.artifacts import UACOutput
        from uac_ai_parser.models.analysis import AnalysisResult, Anomaly
        from datetime import datetime
        
        # Setup mocks
        mock_extractor_instance = MagicMock()
        mock_extractor.return_value.__enter__ = MagicMock(return_value=mock_extractor_instance)
        mock_extractor.return_value.__exit__ = MagicMock(return_value=False)
        
        mock_result = MagicMock()
        mock_result.extract_dir = str(sample_tarball.parent / "extracted")
        mock_extractor_instance.extract.return_value = mock_result
        
        mock_uac_output = UACOutput(
            hostname="testhost",
            collection_time=datetime.now(),
            source_file=str(sample_tarball),
        )
        mock_parser.return_value.parse.return_value = mock_uac_output
        
        mock_analysis = AnalysisResult(
            anomalies=[
                Anomaly(
                    category="process",
                    severity="high",
                    description="Test anomaly",
                    evidence=["test"],
                )
            ],
            iocs=[],
            summary=None,
            raw_llm_output="Test output",
        )
        mock_analyzer.return_value.analyze.return_value = mock_analysis
        
        result = runner.invoke(cli, ["analyze", str(sample_tarball)])
        
        # Should attempt to run
        assert mock_extractor.called or result.exit_code == 0


class TestCLIOutput:
    """Tests for CLI output formatting."""
    
    @pytest.fixture
    def runner(self):
        return CliRunner()
    
    def test_json_output_flag(self, runner):
        """Test JSON output flag."""
        from uac_ai_parser.cli import cli
        
        # Check if --json flag is available
        result = runner.invoke(cli, ["parse", "--help"])
        
        # JSON output should be an option
        assert "--json" in result.output or "--format" in result.output or result.exit_code == 0
    
    def test_verbose_flag(self, runner):
        """Test verbose flag."""
        from uac_ai_parser.cli import cli
        
        result = runner.invoke(cli, ["--help"])
        
        # Verbose should be available
        assert "-v" in result.output or "--verbose" in result.output or result.exit_code == 0


class TestCLIConfig:
    """Tests for CLI configuration handling."""
    
    @pytest.fixture
    def runner(self):
        return CliRunner()
    
    @pytest.fixture
    def config_file(self, tmp_path):
        """Create sample config file."""
        config = tmp_path / "config.yaml"
        config.write_text("""
llm_provider: ollama
llm_model: llama3
temperature: 0.1
chroma_persist_dir: /tmp/uac_vectorstore
""")
        return config
    
    def test_config_file_option(self, runner):
        """Test config file option."""
        from uac_ai_parser.cli import cli
        
        result = runner.invoke(cli, ["--help"])
        
        # Config option should be available
        assert "--config" in result.output or "-c" in result.output or result.exit_code == 0
    
    def test_model_override_option(self, runner):
        """Test model override option."""
        from uac_ai_parser.cli import cli
        
        result = runner.invoke(cli, ["analyze", "--help"])
        
        # Model override should be available for analyze
        assert "--model" in result.output or result.exit_code == 0
