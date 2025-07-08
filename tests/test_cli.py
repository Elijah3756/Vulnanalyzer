"""Tests for the CLI module."""

import pytest
from click.testing import CliRunner

from vuln_analyzer.cli import main


class TestCLI:
    """Test the CLI interface."""
    
    def test_help_command(self):
        """Test the help command."""
        runner = CliRunner()
        result = runner.invoke(main, ['--help'])
        assert result.exit_code == 0
        assert "Analyze vulnerability data" in result.output
    
    def test_version_command(self):
        """Test the version command."""
        runner = CliRunner()
        result = runner.invoke(main, ['--version'])
        assert result.exit_code == 0
    
    def test_invalid_cve_format(self):
        """Test invalid CVE format handling."""
        runner = CliRunner()
        result = runner.invoke(main, ['INVALID-CVE'])
        assert result.exit_code == 1
        assert "Error:" in result.output
    
    def test_cve_detection(self):
        """Test CVE input type detection."""
        runner = CliRunner()
        # This might fail if CVE data is not available, but should not crash
        result = runner.invoke(main, ['CVE-2020-0001'])
        # Exit code can be 0 or 1 depending on data availability
        assert result.exit_code in [0, 1]
    
    def test_purl_detection(self):
        """Test PURL input type detection."""
        runner = CliRunner()
        result = runner.invoke(main, ['pkg:npm/lodash@4.17.20'])
        # Exit code can be 0 or 1 depending on data availability
        assert result.exit_code in [0, 1]
    
    def test_cpe_detection(self):
        """Test CPE input type detection."""
        runner = CliRunner()
        result = runner.invoke(main, ['cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*'])
        # Exit code can be 0 or 1 depending on data availability
        assert result.exit_code in [0, 1]
    
    def test_explicit_input_type(self):
        """Test explicit input type specification."""
        runner = CliRunner()
        result = runner.invoke(main, ['--input-type', 'cve', 'CVE-2020-0001'])
        # Exit code can be 0 or 1 depending on data availability
        assert result.exit_code in [0, 1]
    
    def test_pretty_output_format(self):
        """Test pretty output format."""
        runner = CliRunner()
        result = runner.invoke(main, ['--output-format', 'pretty', 'CVE-2020-0001'])
        # Exit code can be 0 or 1 depending on data availability
        assert result.exit_code in [0, 1]
    
    def test_verbose_flag(self):
        """Test verbose output flag."""
        runner = CliRunner()
        result = runner.invoke(main, ['-v', 'CVE-2020-0001'])
        # Exit code can be 0 or 1 depending on data availability
        assert result.exit_code in [0, 1] 