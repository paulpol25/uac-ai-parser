"""
DFIR-focused prompt templates for LLM analysis.

Contains carefully crafted prompts for forensic analysis tasks
including anomaly detection, incident summarization, and IOC extraction.
"""

from __future__ import annotations

from dataclasses import dataclass
from string import Template


@dataclass
class PromptTemplate:
    """A prompt template with metadata."""
    
    name: str
    description: str
    template: str
    required_vars: list[str]
    
    def format(self, **kwargs) -> str:
        """Format the template with provided variables."""
        return Template(self.template).safe_substitute(**kwargs)


class PromptLibrary:
    """
    Library of DFIR-focused prompt templates.
    
    Provides structured prompts for various forensic analysis tasks.
    """
    
    # System prompt establishing the AI's role
    SYSTEM_PROMPT = """You are an expert Digital Forensics and Incident Response (DFIR) analyst assistant. 
You analyze forensic artifacts from Unix-like systems collected by UAC (Unix-like Artifacts Collector).

Your expertise includes:
- File system analysis (bodyfiles, file metadata, timestamps)
- Process analysis (running processes, suspicious behavior)
- Network forensics (connections, listening services)
- Log analysis (syslog, auth logs, application logs)
- Timeline analysis and event correlation
- Indicator of Compromise (IOC) identification
- Attack pattern recognition (MITRE ATT&CK framework)

Guidelines:
- Be precise and cite specific evidence from the artifacts
- Assign confidence levels to your findings (High/Medium/Low)
- Consider alternative explanations before concluding malicious activity
- Highlight both confirmed findings and areas needing further investigation
- Use proper forensic terminology
- When uncertain, clearly state limitations"""

    # Anomaly detection prompts
    ANOMALY_DETECTION = PromptTemplate(
        name="anomaly_detection",
        description="Analyze artifacts for anomalies and suspicious indicators",
        template="""Analyze the following forensic artifacts for anomalies and suspicious activity.

## Context
Hostname: $hostname
OS Type: $os_type
Collection Time: $collection_time

## Artifacts to Analyze
$artifacts

## Analysis Tasks
1. Identify any suspicious or anomalous entries
2. For each finding, explain WHY it's suspicious
3. Assign a severity (Critical/High/Medium/Low)
4. Assign a confidence score (0.0-1.0)
5. Suggest investigation steps

## Expected Output Format
For each anomaly found:
- **Title**: Brief description
- **Severity**: Critical/High/Medium/Low
- **Confidence**: 0.0-1.0
- **Evidence**: Specific artifact data
- **Analysis**: Why this is suspicious
- **Investigation Steps**: Next steps to investigate

If no anomalies found, explain what was analyzed and why it appears normal.""",
        required_vars=["hostname", "os_type", "collection_time", "artifacts"],
    )
    
    PROCESS_ANALYSIS = PromptTemplate(
        name="process_analysis",
        description="Analyze running processes for suspicious behavior",
        template="""Analyze the following process listing for suspicious activity.

## Process Data
$processes

## Analysis Focus
1. Processes running from unusual locations (/tmp, /var/tmp, /dev/shm)
2. Processes with deleted binary on disk
3. Suspicious command-line arguments
4. Processes running as root that shouldn't be
5. Known malicious process names or patterns
6. Processes masquerading as system processes
7. Unusual parent-child relationships

## Known Good Processes (for reference)
Common legitimate processes: systemd, sshd, cron, rsyslog, nginx, apache2, mysql, postgres

## Output
List findings with:
- Process details (PID, user, command)
- Why it's suspicious
- Severity and confidence
- Recommended investigation steps""",
        required_vars=["processes"],
    )
    
    NETWORK_ANALYSIS = PromptTemplate(
        name="network_analysis",
        description="Analyze network connections for suspicious activity",
        template="""Analyze the following network connections for suspicious activity.

## Network Data
$connections

## Analysis Focus
1. Connections to known malicious ports (4444, 5555, 6666, etc.)
2. Unusual listening services
3. Connections to external IPs that seem suspicious
4. Processes making unexpected network connections
5. Data exfiltration indicators
6. Command & Control (C2) patterns
7. Lateral movement indicators (SSH, SMB connections)

## Output
List findings with:
- Connection details
- Associated process (if known)
- Why it's suspicious
- Potential threat type
- Severity and confidence""",
        required_vars=["connections"],
    )
    
    TIMELINE_ANALYSIS = PromptTemplate(
        name="timeline_analysis",
        description="Analyze timeline for incident reconstruction",
        template="""Analyze the following timeline events to reconstruct potential incident activity.

## Timeline Window
Start: $start_time
End: $end_time

## Timeline Events
$events

## Analysis Tasks
1. Identify clusters of suspicious activity
2. Establish sequence of events
3. Identify potential initial access point
4. Track lateral movement or privilege escalation
5. Note any evidence of data staging or exfiltration
6. Identify persistence mechanisms established

## Output
Provide:
1. **Executive Summary**: Brief overview of findings
2. **Timeline Reconstruction**: Key events in chronological order
3. **Attack Phases Identified**: Map to kill chain if applicable
4. **IOCs Extracted**: Any indicators found
5. **Gaps in Evidence**: What's missing or unclear""",
        required_vars=["start_time", "end_time", "events"],
    )
    
    IOC_EXTRACTION = PromptTemplate(
        name="ioc_extraction",
        description="Extract Indicators of Compromise from artifacts",
        template="""Extract all potential Indicators of Compromise (IOCs) from the following artifacts.

## Artifacts
$artifacts

## IOC Types to Extract
1. **File Hashes**: MD5, SHA1, SHA256
2. **File Paths**: Suspicious file locations
3. **IP Addresses**: External connections
4. **Domains/URLs**: If present in logs
5. **User Accounts**: Suspicious or unauthorized
6. **Process Names**: Malicious executables
7. **Commands**: Suspicious command lines
8. **Registry Keys**: If applicable
9. **Scheduled Tasks/Cron**: Persistence mechanisms

## Output Format
```
IOC_TYPE: value
Context: where it was found
Confidence: High/Medium/Low
```

Group IOCs by type and include context for each.""",
        required_vars=["artifacts"],
    )
    
    INCIDENT_SUMMARY = PromptTemplate(
        name="incident_summary",
        description="Generate executive incident summary",
        template="""Based on the forensic analysis, generate an incident summary report.

## Analysis Results
$analysis_results

## Anomalies Detected
$anomalies

## IOCs Identified
$iocs

## Generate Report Sections

### 1. Executive Summary
- One paragraph summary suitable for management
- Key impact and risk assessment

### 2. Incident Timeline
- When did the incident likely begin?
- Key events in chronological order
- Current status

### 3. Technical Findings
- Detailed technical analysis
- Evidence supporting conclusions
- Confidence levels

### 4. Impact Assessment
- Systems affected
- Data potentially compromised
- Business impact

### 5. Recommendations
- Immediate containment actions
- Short-term remediation
- Long-term improvements

### 6. IOCs for Blocking/Detection
- Actionable IOCs to deploy""",
        required_vars=["analysis_results", "anomalies", "iocs"],
    )
    
    QUERY_RESPONSE = PromptTemplate(
        name="query_response",
        description="Answer user query about forensic data",
        template="""Answer the following question about the forensic data.

## User Question
$query

## Relevant Context
$context

## Guidelines
1. Answer based ONLY on the provided context
2. Cite specific evidence for your conclusions
3. If the context doesn't contain enough information, say so
4. Suggest follow-up queries if helpful
5. Be precise about timestamps and identifiers

## Response Format
- Direct answer to the question
- Supporting evidence (with quotes from context)
- Confidence level
- Suggested follow-up queries (if applicable)""",
        required_vars=["query", "context"],
    )
    
    LATERAL_MOVEMENT = PromptTemplate(
        name="lateral_movement",
        description="Detect lateral movement indicators",
        template="""Analyze the following artifacts for lateral movement indicators.

## Artifacts
$artifacts

## Lateral Movement Techniques to Look For
1. **SSH Activity**: New connections, key-based auth, unusual source IPs
2. **Remote Execution**: psexec-like behavior, remote scripts
3. **Credential Usage**: Different users from same source, pass-the-hash
4. **Network Scanning**: Connection attempts to multiple hosts
5. **File Transfers**: scp, rsync, unusual file copies
6. **Admin Tool Usage**: Remote admin tools, WMI-like activity

## Network Connections Context
$network

## Process Context
$processes

## Authentication Logs (if available)
$auth_logs

## Output
For each lateral movement indicator found:
- Technique identified
- Evidence supporting detection
- Source and destination systems
- Timestamps
- Confidence level
- MITRE ATT&CK mapping if applicable""",
        required_vars=["artifacts", "network", "processes", "auth_logs"],
    )
    
    PERSISTENCE_DETECTION = PromptTemplate(
        name="persistence_detection",
        description="Detect persistence mechanisms",
        template="""Analyze artifacts for persistence mechanisms that could allow an attacker to maintain access.

## File System Data
$filesystem

## Configuration Files
$configs

## Scheduled Tasks/Cron
$cron

## Service Information
$services

## Persistence Techniques to Detect
1. **Cron Jobs**: New or modified cron entries
2. **Systemd Services**: Unauthorized services
3. **Init Scripts**: Modified startup scripts
4. **Shell Profiles**: .bashrc, .profile modifications
5. **SSH Keys**: Unauthorized authorized_keys entries
6. **Kernel Modules**: Suspicious loaded modules
7. **LD_PRELOAD**: Hijacked library loading
8. **Setuid Binaries**: New or modified SUID files
9. **Web Shells**: PHP/JSP files in web directories
10. **Rootkits**: Hidden files, processes, or connections

## Output
For each persistence mechanism found:
- Type of persistence
- Location/path
- Evidence
- Risk level
- Removal steps""",
        required_vars=["filesystem", "configs", "cron", "services"],
    )
    
    @classmethod
    def get_prompt(cls, name: str) -> PromptTemplate | None:
        """Get a prompt template by name."""
        prompts = {
            "anomaly_detection": cls.ANOMALY_DETECTION,
            "process_analysis": cls.PROCESS_ANALYSIS,
            "network_analysis": cls.NETWORK_ANALYSIS,
            "timeline_analysis": cls.TIMELINE_ANALYSIS,
            "ioc_extraction": cls.IOC_EXTRACTION,
            "incident_summary": cls.INCIDENT_SUMMARY,
            "query_response": cls.QUERY_RESPONSE,
            "lateral_movement": cls.LATERAL_MOVEMENT,
            "persistence_detection": cls.PERSISTENCE_DETECTION,
        }
        return prompts.get(name)
    
    @classmethod
    def list_prompts(cls) -> list[str]:
        """List available prompt names."""
        return [
            "anomaly_detection",
            "process_analysis", 
            "network_analysis",
            "timeline_analysis",
            "ioc_extraction",
            "incident_summary",
            "query_response",
            "lateral_movement",
            "persistence_detection",
        ]
