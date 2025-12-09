"""
Tests for bodyfile parsing.
"""

import pytest
from uac_ai_parser.models.artifacts import BodyfileEntry, Bodyfile


class TestBodyfileEntry:
    """Tests for BodyfileEntry model."""
    
    def test_parse_simple_line(self):
        """Test parsing a simple bodyfile line."""
        line = "d41d8cd98f00b204e9800998ecf8427e|/usr/bin/test|12345|-rwxr-xr-x|0|0|1024|1609459200|1609459200|1609459200|1609459200"
        
        entry = BodyfileEntry.from_line(line)
        
        assert entry.md5 == "d41d8cd98f00b204e9800998ecf8427e"
        assert entry.name == "/usr/bin/test"
        assert entry.inode == "12345"
        assert entry.mode == "-rwxr-xr-x"
        assert entry.uid == 0
        assert entry.gid == 0
        assert entry.size == 1024
        assert entry.atime == 1609459200
        assert entry.mtime == 1609459200
        assert entry.ctime == 1609459200
        assert entry.crtime == 1609459200
    
    def test_parse_line_with_missing_hash(self):
        """Test parsing line with no hash."""
        line = "0|/etc/passwd|100|-rw-r--r--|0|0|2048|1609459200|1609459200|1609459200|0"
        
        entry = BodyfileEntry.from_line(line)
        
        assert entry.md5 == "0"
        assert entry.name == "/etc/passwd"
    
    def test_is_executable(self):
        """Test executable detection."""
        executable_line = "0|/usr/bin/bash|1|-rwxr-xr-x|0|0|100|0|0|0|0"
        non_executable_line = "0|/etc/passwd|2|-rw-r--r--|0|0|100|0|0|0|0"
        
        exec_entry = BodyfileEntry.from_line(executable_line)
        non_exec_entry = BodyfileEntry.from_line(non_executable_line)
        
        assert exec_entry.is_executable is True
        assert non_exec_entry.is_executable is False
    
    def test_is_setuid(self):
        """Test SUID detection."""
        suid_line = "0|/usr/bin/sudo|1|-rwsr-xr-x|0|0|100|0|0|0|0"
        normal_line = "0|/usr/bin/ls|2|-rwxr-xr-x|0|0|100|0|0|0|0"
        
        suid_entry = BodyfileEntry.from_line(suid_line)
        normal_entry = BodyfileEntry.from_line(normal_line)
        
        assert suid_entry.is_setuid is True
        assert normal_entry.is_setuid is False
    
    def test_is_directory(self):
        """Test directory detection."""
        dir_line = "0|/var/log|1|drwxr-xr-x|0|0|4096|0|0|0|0"
        file_line = "0|/var/log/syslog|2|-rw-r--r--|0|0|1024|0|0|0|0"
        
        dir_entry = BodyfileEntry.from_line(dir_line)
        file_entry = BodyfileEntry.from_line(file_line)
        
        assert dir_entry.is_directory is True
        assert file_entry.is_directory is False
    
    def test_filename_extraction(self):
        """Test filename extraction from path."""
        line = "0|/var/log/auth.log|1|-rw-r--r--|0|0|1024|0|0|0|0"
        
        entry = BodyfileEntry.from_line(line)
        
        assert entry.filename == "auth.log"
        assert entry.directory == "/var/log"
    
    def test_timestamp_conversion(self):
        """Test timestamp to datetime conversion."""
        line = "0|/test|1|-rw-r--r--|0|0|0|1609459200|1609459200|1609459200|1609459200"
        
        entry = BodyfileEntry.from_line(line)
        
        assert entry.mtime_dt is not None
        assert entry.mtime_dt.year == 2021
        assert entry.mtime_dt.month == 1
        assert entry.mtime_dt.day == 1


class TestBodyfile:
    """Tests for Bodyfile collection."""
    
    def test_filter_executables(self):
        """Test filtering for executables."""
        entries = [
            BodyfileEntry.from_line("0|/usr/bin/bash|1|-rwxr-xr-x|0|0|100|0|0|0|0"),
            BodyfileEntry.from_line("0|/etc/passwd|2|-rw-r--r--|0|0|100|0|0|0|0"),
            BodyfileEntry.from_line("0|/usr/bin/ls|3|-rwxr-xr-x|0|0|100|0|0|0|0"),
        ]
        
        bodyfile = Bodyfile(entries=entries)
        
        executables = bodyfile.executables
        assert len(executables) == 2
        assert all(e.is_executable for e in executables)
    
    def test_filter_setuid(self):
        """Test filtering for SUID files."""
        entries = [
            BodyfileEntry.from_line("0|/usr/bin/sudo|1|-rwsr-xr-x|0|0|100|0|0|0|0"),
            BodyfileEntry.from_line("0|/usr/bin/passwd|2|-rwsr-xr-x|0|0|100|0|0|0|0"),
            BodyfileEntry.from_line("0|/usr/bin/ls|3|-rwxr-xr-x|0|0|100|0|0|0|0"),
        ]
        
        bodyfile = Bodyfile(entries=entries)
        
        setuid_files = bodyfile.setuid_files
        assert len(setuid_files) == 2
    
    def test_filter_by_path(self):
        """Test filtering by path pattern."""
        entries = [
            BodyfileEntry.from_line("0|/var/log/syslog|1|-rw-r--r--|0|0|100|0|0|0|0"),
            BodyfileEntry.from_line("0|/var/log/auth.log|2|-rw-r--r--|0|0|100|0|0|0|0"),
            BodyfileEntry.from_line("0|/etc/passwd|3|-rw-r--r--|0|0|100|0|0|0|0"),
        ]
        
        bodyfile = Bodyfile(entries=entries)
        
        log_files = bodyfile.filter_by_path("/var/log/*")
        assert len(log_files) == 2
    
    def test_total_entries(self):
        """Test entry count."""
        entries = [
            BodyfileEntry.from_line("0|/file1|1|-rw-r--r--|0|0|100|0|0|0|0"),
            BodyfileEntry.from_line("0|/file2|2|-rw-r--r--|0|0|100|0|0|0|0"),
        ]
        
        bodyfile = Bodyfile(entries=entries)
        
        assert bodyfile.total_entries == 2


class TestMalformedInput:
    """Tests for handling malformed input."""
    
    def test_incomplete_line(self):
        """Test parsing incomplete bodyfile line."""
        line = "0|/test|123"  # Missing fields
        
        entry = BodyfileEntry.from_line(line)
        
        assert entry.name == "/test"
        assert entry.inode == "123"
        # Missing fields should have defaults
        assert entry.mode == ""
        assert entry.uid == 0
    
    def test_empty_line(self):
        """Test parsing empty line."""
        entry = BodyfileEntry.from_line("")
        
        assert entry.name == ""
    
    def test_non_numeric_values(self):
        """Test handling non-numeric values gracefully."""
        line = "0|/test|abc|mode|notanumber|0|0|0|0|0|0"
        
        entry = BodyfileEntry.from_line(line)
        
        assert entry.uid == 0  # Should use default for invalid int
