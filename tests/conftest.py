"""
Pytest configuration and shared fixtures.
"""

import pytest
import tempfile
import tarfile
from pathlib import Path
from datetime import datetime

from uac_ai_parser.models.artifacts import (
    UACOutput, Bodyfile, BodyfileEntry, ProcessInfo,
    NetworkConnection, UserInfo, LogEntry
)


@pytest.fixture
def tmp_workspace(tmp_path):
    """Create a temporary workspace directory."""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return workspace


@pytest.fixture
def sample_bodyfile_content():
    """Sample bodyfile content for testing."""
    return """0|/usr/bin/bash|12345|-rwxr-xr-x|0|0|1234567|1702100000|1702100000|1702100000|1702100000
0|/etc/passwd|11111|-rw-r--r--|0|0|2048|1700000000|1700000000|1700000000|1700000000
d41d8cd98f00b204e9800998ecf8427e|/usr/bin/sudo|22222|-rwsr-xr-x|0|0|200000|1698000000|1698000000|1698000000|1698000000
abc123def456|/tmp/.hidden/backdoor|99999|-rwxr-xr-x|1000|1000|50000|1702150000|1702150000|1702150000|1702150000
"""


@pytest.fixture
def sample_bodyfile(tmp_path, sample_bodyfile_content):
    """Create a sample bodyfile."""
    bodyfile = tmp_path / "bodyfile.txt"
    bodyfile.write_text(sample_bodyfile_content)
    return bodyfile


@pytest.fixture
def sample_ps_output():
    """Sample ps auxwww output."""
    return """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 168936 11788 ?        Ss   Dec08   0:02 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Dec08   0:00 [kthreadd]
www-data  1234  0.5  2.0 512000 40000 ?        S    Dec08   1:00 /usr/sbin/apache2 -k start
nobody    9999 50.0  5.0 100000 50000 ?        R    Dec09  10:00 /tmp/.hidden/miner --cpu
root       666  1.0  0.5  50000 10000 ?        S    Dec09   0:30 /tmp/backdoor --connect 10.10.10.10
"""


@pytest.fixture
def sample_netstat_output():
    """Sample netstat -tunap output."""
    return """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      100/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1234/apache2
tcp        0      0 192.168.1.100:45678     10.10.10.10:4444        ESTABLISHED 666/backdoor
tcp        0      0 192.168.1.100:55555     1.2.3.4:443             ESTABLISHED 2000/curl
udp        0      0 0.0.0.0:53              0.0.0.0:*                           200/dnsmasq
"""


@pytest.fixture
def sample_uac_structure(tmp_path, sample_bodyfile_content, sample_ps_output, sample_netstat_output):
    """Create a complete sample UAC directory structure."""
    # Base directory
    uac_dir = tmp_path / "uac-testhost-linux-20231209120000"
    uac_dir.mkdir()
    
    # Bodyfile
    bodyfile_dir = uac_dir / "bodyfile"
    bodyfile_dir.mkdir()
    (bodyfile_dir / "bodyfile.txt").write_text(sample_bodyfile_content)
    
    # Live response - process
    process_dir = uac_dir / "live_response" / "process"
    process_dir.mkdir(parents=True)
    (process_dir / "ps_auxwww.txt").write_text(sample_ps_output)
    
    # Live response - network
    network_dir = uac_dir / "live_response" / "network"
    network_dir.mkdir(parents=True)
    (network_dir / "netstat_-tunap.txt").write_text(sample_netstat_output)
    
    # Live response - user
    user_dir = uac_dir / "live_response" / "user"
    user_dir.mkdir(parents=True)
    (user_dir / "etc_passwd.txt").write_text("""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
attacker:x:1001:1001::/home/attacker:/bin/bash
""")
    
    # Live response - system logs
    system_dir = uac_dir / "live_response" / "system"
    system_dir.mkdir(parents=True)
    (system_dir / "var_log_auth.log").write_text("""Dec  9 10:00:00 testhost sshd[100]: Accepted publickey for root from 192.168.1.1 port 50000
Dec  9 10:30:00 testhost sshd[200]: Failed password for root from 10.10.10.10 port 44444
Dec  9 10:31:00 testhost sshd[200]: Failed password for root from 10.10.10.10 port 44444
Dec  9 10:32:00 testhost sshd[200]: Accepted password for root from 10.10.10.10 port 44444
Dec  9 10:35:00 testhost sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash
""")
    
    # UAC log
    (uac_dir / "uac.log").write_text("""UAC (Unix-like Artifacts Collector)
Version: 2.9.0
Hostname: testhost
Start time: 2023-12-09 12:00:00
""")
    
    return uac_dir


@pytest.fixture
def sample_uac_tarball(tmp_path, sample_uac_structure):
    """Create a sample UAC tarball from the structure."""
    tarball_path = tmp_path / "uac-testhost-linux-20231209120000.tar.gz"
    
    with tarfile.open(tarball_path, "w:gz") as tar:
        tar.add(sample_uac_structure, arcname=sample_uac_structure.name)
    
    return tarball_path


@pytest.fixture
def sample_bodyfile_entries():
    """Create sample BodyfileEntry objects."""
    return [
        BodyfileEntry(
            md5="0",
            path="/usr/bin/bash",
            inode=12345,
            mode="-rwxr-xr-x",
            uid=0,
            gid=0,
            size=1234567,
            atime=datetime(2023, 12, 9, 10, 0, 0),
            mtime=datetime(2023, 12, 9, 10, 0, 0),
            ctime=datetime(2023, 12, 9, 10, 0, 0),
            crtime=datetime(2023, 12, 9, 10, 0, 0),
        ),
        BodyfileEntry(
            md5="abc123def456",
            path="/tmp/.hidden/backdoor",
            inode=99999,
            mode="-rwxr-xr-x",
            uid=1000,
            gid=1000,
            size=50000,
            atime=datetime(2023, 12, 9, 14, 0, 0),
            mtime=datetime(2023, 12, 9, 14, 0, 0),
            ctime=datetime(2023, 12, 9, 14, 0, 0),
            crtime=datetime(2023, 12, 9, 14, 0, 0),
        ),
    ]


@pytest.fixture
def sample_uac_output(sample_bodyfile_entries):
    """Create a sample UACOutput object."""
    bodyfile = Bodyfile(
        entries=sample_bodyfile_entries,
        source_file="/test/bodyfile.txt"
    )
    
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
            user="root",
            command="/tmp/backdoor --connect 10.10.10.10",
            cpu_percent=1.0,
            memory_percent=0.5,
        ),
        ProcessInfo(
            pid=9999,
            ppid=1,
            user="nobody",
            command="/tmp/.hidden/miner --cpu",
            cpu_percent=50.0,
            memory_percent=5.0,
        ),
    ]
    
    connections = [
        NetworkConnection(
            protocol="tcp",
            local_address="0.0.0.0",
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
    
    users = [
        UserInfo(username="root", uid=0, gid=0, home="/root", shell="/bin/bash"),
        UserInfo(username="attacker", uid=1001, gid=1001, home="/home/attacker", shell="/bin/bash"),
    ]
    
    logs = [
        LogEntry(
            timestamp=datetime(2023, 12, 9, 10, 32, 0),
            source="auth.log",
            message="Accepted password for root from 10.10.10.10 port 44444",
            level="INFO",
        ),
        LogEntry(
            timestamp=datetime(2023, 12, 9, 10, 35, 0),
            source="auth.log",
            message="attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash",
            level="WARNING",
        ),
    ]
    
    return UACOutput(
        hostname="testhost",
        collection_time=datetime(2023, 12, 9, 12, 0, 0),
        source_file="/test/uac-testhost.tar.gz",
        bodyfile=bodyfile,
        processes=processes,
        network_connections=connections,
        users=users,
        logs=logs,
    )


# Markers for conditional test execution
def pytest_configure(config):
    """Configure custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "requires_llm: marks tests that require LLM connection"
    )
    config.addinivalue_line(
        "markers", "requires_docker: marks tests that require Docker"
    )
