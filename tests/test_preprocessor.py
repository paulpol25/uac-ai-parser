"""
Tests for the preprocessor module.
"""

import pytest
from pathlib import Path
from datetime import datetime

from uac_ai_parser.core.preprocessor import Preprocessor
from uac_ai_parser.models.artifacts import (
    UACOutput, Bodyfile, BodyfileEntry, ProcessInfo, 
    NetworkConnection, LogEntry
)


class TestPreprocessor:
    """Tests for Preprocessor class."""
    
    @pytest.fixture
    def sample_uac_output(self):
        """Create sample UACOutput for testing."""
        # Create bodyfile entries
        bodyfile_entries = [
            BodyfileEntry(
                md5="d41d8cd98f00b204e9800998ecf8427e",
                path=f"/usr/bin/file{i}",
                inode=i,
                mode="-rwxr-xr-x",
                uid=0,
                gid=0,
                size=1000 * i,
                atime=datetime(2023, 12, 9, 10, 0, 0),
                mtime=datetime(2023, 12, 9, 10, 0, 0),
                ctime=datetime(2023, 12, 9, 10, 0, 0),
                crtime=datetime(2023, 12, 9, 10, 0, 0),
            )
            for i in range(150)  # More than default chunk size
        ]
        
        # Add suspicious files
        bodyfile_entries.extend([
            BodyfileEntry(
                md5="abc123",
                path="/tmp/.hidden/backdoor",
                inode=99999,
                mode="-rwxr-xr-x",
                uid=0,
                gid=0,
                size=50000,
                atime=datetime(2023, 12, 9, 12, 0, 0),
                mtime=datetime(2023, 12, 9, 12, 0, 0),
                ctime=datetime(2023, 12, 9, 12, 0, 0),
                crtime=datetime(2023, 12, 9, 12, 0, 0),
            ),
            BodyfileEntry(
                md5="def456",
                path="/var/tmp/nc",
                inode=88888,
                mode="-rwxr-xr-x",
                uid=1000,
                gid=1000,
                size=30000,
                atime=datetime(2023, 12, 9, 11, 0, 0),
                mtime=datetime(2023, 12, 9, 11, 0, 0),
                ctime=datetime(2023, 12, 9, 11, 0, 0),
                crtime=datetime(2023, 12, 9, 11, 0, 0),
            ),
        ])
        
        bodyfile = Bodyfile(entries=bodyfile_entries, source_file="/test/bodyfile.txt")
        
        # Create processes
        processes = [
            ProcessInfo(
                pid=1,
                ppid=0,
                user="root",
                command="/sbin/init",
                cpu_percent=0.0,
                memory_percent=0.1,
            ),
            ProcessInfo(
                pid=666,
                ppid=1,
                user="nobody",
                command="/tmp/.hidden/backdoor --connect 10.10.10.10",
                cpu_percent=50.0,
                memory_percent=5.0,
            ),
        ]
        
        # Create network connections
        connections = [
            NetworkConnection(
                protocol="tcp",
                local_address="192.168.1.100",
                local_port=22,
                remote_address="0.0.0.0",
                remote_port=0,
                state="LISTEN",
                pid=100,
                program="sshd",
            ),
            NetworkConnection(
                protocol="tcp",
                local_address="192.168.1.100",
                local_port=45678,
                remote_address="10.10.10.10",
                remote_port=4444,
                state="ESTABLISHED",
                pid=666,
                program="backdoor",
            ),
        ]
        
        # Create logs
        logs = [
            LogEntry(
                timestamp=datetime(2023, 12, 9, 10, 0, 0),
                source="syslog",
                message="System started",
                level="INFO",
            ),
            LogEntry(
                timestamp=datetime(2023, 12, 9, 12, 0, 0),
                source="auth.log",
                message="Failed password for root from 10.10.10.10",
                level="WARNING",
            ),
        ]
        
        return UACOutput(
            hostname="testhost",
            collection_time=datetime(2023, 12, 9, 12, 0, 0),
            source_file="/test/uac.tar.gz",
            bodyfile=bodyfile,
            processes=processes,
            network_connections=connections,
            logs=logs,
        )
    
    def test_preprocess_returns_documents(self, sample_uac_output):
        """Test that preprocessing returns document list."""
        preprocessor = Preprocessor()
        documents = preprocessor.preprocess(sample_uac_output)
        
        assert len(documents) > 0
        assert all(hasattr(doc, "page_content") for doc in documents)
        assert all(hasattr(doc, "metadata") for doc in documents)
    
    def test_bodyfile_chunking(self, sample_uac_output):
        """Test that bodyfile is properly chunked."""
        preprocessor = Preprocessor(max_chunk_size=50)
        documents = preprocessor.preprocess(sample_uac_output)
        
        bodyfile_docs = [d for d in documents if d.metadata.get("type") == "bodyfile"]
        
        # Should have multiple chunks due to 150+ entries
        assert len(bodyfile_docs) > 1
    
    def test_document_metadata(self, sample_uac_output):
        """Test that documents have proper metadata."""
        preprocessor = Preprocessor()
        documents = preprocessor.preprocess(sample_uac_output)
        
        for doc in documents:
            assert "type" in doc.metadata
            assert "hostname" in doc.metadata
            assert doc.metadata["hostname"] == "testhost"
    
    def test_process_documents(self, sample_uac_output):
        """Test process information is included."""
        preprocessor = Preprocessor()
        documents = preprocessor.preprocess(sample_uac_output)
        
        process_docs = [d for d in documents if d.metadata.get("type") == "process"]
        assert len(process_docs) > 0
        
        # Check suspicious process is captured
        all_content = " ".join(d.page_content for d in process_docs)
        assert "backdoor" in all_content.lower()
    
    def test_network_documents(self, sample_uac_output):
        """Test network connections are included."""
        preprocessor = Preprocessor()
        documents = preprocessor.preprocess(sample_uac_output)
        
        network_docs = [d for d in documents if d.metadata.get("type") == "network"]
        assert len(network_docs) > 0
        
        # Check suspicious connection is captured
        all_content = " ".join(d.page_content for d in network_docs)
        assert "10.10.10.10" in all_content
    
    def test_log_documents(self, sample_uac_output):
        """Test log entries are included."""
        preprocessor = Preprocessor()
        documents = preprocessor.preprocess(sample_uac_output)
        
        log_docs = [d for d in documents if d.metadata.get("type") == "log"]
        assert len(log_docs) > 0
    
    def test_empty_input(self):
        """Test handling of empty UACOutput."""
        empty_output = UACOutput(
            hostname="empty",
            collection_time=datetime.now(),
            source_file="/test/empty.tar.gz",
        )
        
        preprocessor = Preprocessor()
        documents = preprocessor.preprocess(empty_output)
        
        # Should still return something (at least metadata)
        assert isinstance(documents, list)
    
    def test_custom_chunk_size(self, sample_uac_output):
        """Test custom chunk size."""
        small_chunks = Preprocessor(max_chunk_size=10)
        large_chunks = Preprocessor(max_chunk_size=500)
        
        small_docs = small_chunks.preprocess(sample_uac_output)
        large_docs = large_chunks.preprocess(sample_uac_output)
        
        # Smaller chunks should produce more documents
        small_bodyfile = [d for d in small_docs if d.metadata.get("type") == "bodyfile"]
        large_bodyfile = [d for d in large_docs if d.metadata.get("type") == "bodyfile"]
        
        assert len(small_bodyfile) > len(large_bodyfile)


class TestDocumentContent:
    """Tests for document content formatting."""
    
    def test_bodyfile_document_format(self):
        """Test bodyfile entry formatting."""
        entry = BodyfileEntry(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            path="/usr/bin/test",
            inode=12345,
            mode="-rwxr-xr-x",
            uid=0,
            gid=0,
            size=1000,
            atime=datetime(2023, 12, 9, 10, 0, 0),
            mtime=datetime(2023, 12, 9, 11, 0, 0),
            ctime=datetime(2023, 12, 9, 12, 0, 0),
            crtime=datetime(2023, 12, 9, 9, 0, 0),
        )
        
        bodyfile = Bodyfile(entries=[entry], source_file="/test/bodyfile.txt")
        uac_output = UACOutput(
            hostname="test",
            collection_time=datetime.now(),
            source_file="/test.tar.gz",
            bodyfile=bodyfile,
        )
        
        preprocessor = Preprocessor()
        documents = preprocessor.preprocess(uac_output)
        
        bodyfile_docs = [d for d in documents if d.metadata.get("type") == "bodyfile"]
        assert len(bodyfile_docs) > 0
        
        content = bodyfile_docs[0].page_content
        assert "/usr/bin/test" in content
        assert "d41d8cd98f00b204e9800998ecf8427e" in content
    
    def test_suspicious_file_highlighting(self):
        """Test that suspicious paths are identifiable."""
        suspicious_paths = [
            "/tmp/.hidden/malware",
            "/dev/shm/backdoor",
            "/var/tmp/nc",
            "/tmp/cronrootkit",
        ]
        
        entries = [
            BodyfileEntry(
                md5="abc123",
                path=path,
                inode=i,
                mode="-rwxr-xr-x",
                uid=0,
                gid=0,
                size=1000,
                atime=datetime.now(),
                mtime=datetime.now(),
                ctime=datetime.now(),
                crtime=datetime.now(),
            )
            for i, path in enumerate(suspicious_paths)
        ]
        
        bodyfile = Bodyfile(entries=entries, source_file="/test/bodyfile.txt")
        uac_output = UACOutput(
            hostname="test",
            collection_time=datetime.now(),
            source_file="/test.tar.gz",
            bodyfile=bodyfile,
        )
        
        preprocessor = Preprocessor()
        documents = preprocessor.preprocess(uac_output)
        
        all_content = " ".join(d.page_content for d in documents)
        
        for path in suspicious_paths:
            assert path in all_content
