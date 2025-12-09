"""
Tests for the main UAC parser.
"""

import pytest
from pathlib import Path
from datetime import datetime

from uac_ai_parser.core.parser import UACParser
from uac_ai_parser.models.artifacts import UACOutput


class TestUACParser:
    """Tests for UACParser class."""
    
    @pytest.fixture
    def sample_uac_structure(self, tmp_path):
        """Create a sample UAC directory structure."""
        # Create base directory
        uac_dir = tmp_path / "uac-testhost-linux-20231209"
        uac_dir.mkdir()
        
        # Create bodyfile
        bodyfile_dir = uac_dir / "bodyfile"
        bodyfile_dir.mkdir()
        bodyfile = bodyfile_dir / "bodyfile.txt"
        bodyfile.write_text("""0|/usr/bin/bash|12345|-rwxr-xr-x|0|0|1234567|1702100000|1702100000|1702100000|1702100000
0|/etc/passwd|11111|-rw-r--r--|0|0|2000|1700000000|1700000000|1700000000|1700000000
""")
        
        # Create live_response process directory
        process_dir = uac_dir / "live_response" / "process"
        process_dir.mkdir(parents=True)
        
        # ps output
        ps_file = process_dir / "ps_auxwww.txt"
        ps_file.write_text("""USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168936 11788 ?        Ss   Dec08   0:02 /sbin/init
nobody    2222  1.0  0.5 100000 10000 ?        S    Dec08   2:00 /suspicious/binary
""")
        
        # Create network directory
        network_dir = uac_dir / "live_response" / "network"
        network_dir.mkdir(parents=True)
        
        # netstat output
        netstat_file = network_dir / "netstat_-tunap.txt"
        netstat_file.write_text("""Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1234/sshd
tcp        0      0 192.168.1.100:45678     10.10.10.10:4444        ESTABLISHED 9999/nc
""")
        
        # Create user directory
        user_dir = uac_dir / "live_response" / "user"
        user_dir.mkdir(parents=True)
        
        # passwd file
        passwd_file = user_dir / "etc_passwd.txt"
        passwd_file.write_text("""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
hacker:x:1001:1001::/home/hacker:/bin/bash
""")
        
        # Create system log directory
        log_dir = uac_dir / "live_response" / "system"
        log_dir.mkdir(parents=True)
        
        # syslog
        syslog = log_dir / "var_log_syslog.txt"
        syslog.write_text("""Dec  9 10:00:00 testhost sshd[1234]: Accepted publickey for root
Dec  9 10:05:00 testhost kernel: [ERROR] suspicious module loaded
Dec  9 10:10:00 testhost cron[5555]: (CRON) CMD (/tmp/.hidden/backdoor)
""")
        
        return uac_dir
    
    def test_parse_basic(self, sample_uac_structure):
        """Test basic parsing of UAC output."""
        parser = UACParser(sample_uac_structure)
        result = parser.parse()
        
        assert isinstance(result, UACOutput)
        assert result.hostname is not None
    
    def test_parse_bodyfile(self, sample_uac_structure):
        """Test bodyfile parsing."""
        parser = UACParser(sample_uac_structure)
        result = parser.parse()
        
        assert result.bodyfile is not None
        assert len(result.bodyfile.entries) == 2
        assert any("/usr/bin/bash" in e.path for e in result.bodyfile.entries)
    
    def test_parse_processes(self, sample_uac_structure):
        """Test process parsing."""
        parser = UACParser(sample_uac_structure)
        result = parser.parse()
        
        assert len(result.processes) > 0
        # Check for suspicious process
        suspicious = [p for p in result.processes if "suspicious" in p.command.lower()]
        assert len(suspicious) > 0
    
    def test_parse_network(self, sample_uac_structure):
        """Test network connection parsing."""
        parser = UACParser(sample_uac_structure)
        result = parser.parse()
        
        assert len(result.network_connections) > 0
        # Check for suspicious connection to external IP
        suspicious = [c for c in result.network_connections 
                     if c.remote_address == "10.10.10.10"]
        assert len(suspicious) > 0
    
    def test_parse_users(self, sample_uac_structure):
        """Test user parsing."""
        parser = UACParser(sample_uac_structure)
        result = parser.parse()
        
        assert len(result.users) > 0
        # Check for suspicious user
        usernames = [u.username for u in result.users]
        assert "hacker" in usernames
    
    def test_parse_logs(self, sample_uac_structure):
        """Test log parsing."""
        parser = UACParser(sample_uac_structure)
        result = parser.parse()
        
        assert len(result.logs) > 0
    
    def test_parse_metadata(self, sample_uac_structure):
        """Test metadata extraction."""
        parser = UACParser(sample_uac_structure)
        result = parser.parse()
        
        assert result.collection_time is not None or result.hostname is not None
    
    def test_empty_directory(self, tmp_path):
        """Test handling of empty directory."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        
        parser = UACParser(empty_dir)
        result = parser.parse()
        
        assert isinstance(result, UACOutput)
        assert result.bodyfile is None or len(result.bodyfile.entries) == 0


class TestProcessParsing:
    """Detailed tests for process parsing."""
    
    @pytest.fixture
    def ps_output(self, tmp_path):
        """Create ps output file."""
        ps_file = tmp_path / "ps_auxwww.txt"
        ps_file.write_text("""USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168936 11788 ?        Ss   Dec08   0:02 /sbin/init
root        10  50.0  5.0 500000 100000 ?      R    Dec09  10:00 /tmp/miner --cpu
www-data  3000  0.1  0.2  50000  4000 ?        S    Dec08   0:30 /usr/sbin/apache2 -k start
""")
        return ps_file
    
    def test_parse_process_fields(self, ps_output, tmp_path):
        """Test that process fields are correctly parsed."""
        # Create minimal UAC structure
        uac_dir = tmp_path / "uac-test"
        uac_dir.mkdir()
        process_dir = uac_dir / "live_response" / "process"
        process_dir.mkdir(parents=True)
        
        import shutil
        shutil.copy(ps_output, process_dir / "ps_auxwww.txt")
        
        parser = UACParser(uac_dir)
        result = parser.parse()
        
        # Find the miner process
        miner = next((p for p in result.processes if "miner" in p.command), None)
        assert miner is not None
        assert miner.pid == 10
        assert miner.user == "root"
        assert miner.cpu_percent == 50.0
        assert miner.memory_percent == 5.0


class TestNetworkParsing:
    """Detailed tests for network connection parsing."""
    
    def test_parse_established_connections(self, tmp_path):
        """Test parsing of established connections."""
        uac_dir = tmp_path / "uac-test"
        network_dir = uac_dir / "live_response" / "network"
        network_dir.mkdir(parents=True)
        
        netstat = network_dir / "netstat_-tunap.txt"
        netstat.write_text("""Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 192.168.1.100:443       0.0.0.0:*               LISTEN      80/nginx
tcp        0      0 192.168.1.100:55555     1.2.3.4:443             ESTABLISHED 1000/curl
tcp        0      0 192.168.1.100:12345     5.6.7.8:4444            ESTABLISHED 9999/reverse_shell
udp        0      0 0.0.0.0:53              0.0.0.0:*                           53/dnsmasq
""")
        
        parser = UACParser(uac_dir)
        result = parser.parse()
        
        # Check connections were parsed
        assert len(result.network_connections) >= 2
        
        # Check for suspicious connection
        suspicious = [c for c in result.network_connections 
                     if c.remote_port == 4444]
        assert len(suspicious) > 0
    
    def test_parse_listening_ports(self, tmp_path):
        """Test parsing of listening ports."""
        uac_dir = tmp_path / "uac-test"
        network_dir = uac_dir / "live_response" / "network"
        network_dir.mkdir(parents=True)
        
        netstat = network_dir / "netstat_-tunap.txt"
        netstat.write_text("""Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      100/sshd
tcp        0      0 0.0.0.0:31337           0.0.0.0:*               LISTEN      666/backdoor
""")
        
        parser = UACParser(uac_dir)
        result = parser.parse()
        
        listening = [c for c in result.network_connections if c.state == "LISTEN"]
        assert len(listening) >= 2
        
        # Check for suspicious port
        suspicious_ports = [c for c in listening if c.local_port == 31337]
        assert len(suspicious_ports) > 0
