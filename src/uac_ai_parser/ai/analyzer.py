"""
AI Analyzer - Main orchestrator for AI-powered forensic analysis.

Combines LLM inference, RAG retrieval, and DFIR-focused prompts
for comprehensive artifact analysis.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from uac_ai_parser.ai.llm import LLMClient, LLMConfig, BaseLLMClient
from uac_ai_parser.ai.prompts import PromptLibrary
from uac_ai_parser.ai.vectorstore import VectorStore
from uac_ai_parser.core.preprocessor import Preprocessor, DocumentChunk
from uac_ai_parser.models.artifacts import UACOutput
from uac_ai_parser.models.analysis import (
    AnalysisResult,
    AnomalyReport,
    Anomaly,
    AnomalyType,
    AnomalySeverity,
    QueryResult,
    Evidence,
    IncidentSummary,
)

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    AI-powered analyzer for UAC forensic artifacts.
    
    Provides:
    - Anomaly detection with confidence scoring
    - Natural language queries against forensic data
    - Incident summarization
    - IOC extraction
    - Timeline correlation
    
    Example:
        ```python
        analyzer = AIAnalyzer(model="llama3.1")
        analyzer.load_artifacts(uac_output)
        
        # Detect anomalies
        anomalies = analyzer.detect_anomalies()
        print(anomalies.to_markdown())
        
        # Query the data
        result = analyzer.query("What SSH activity occurred?")
        print(result.answer)
        
        # Generate incident summary
        summary = analyzer.generate_summary()
        print(summary.to_markdown())
        ```
    """
    
    def __init__(
        self,
        model: str = "llama3.1",
        provider: str = "ollama",
        base_url: str = "http://localhost:11434",
        api_key: str | None = None,
        persist_vectors: bool = True,
        vector_dir: str | Path | None = None,
        temperature: float = 0.1,
    ):
        """
        Initialize the AI analyzer.
        
        Args:
            model: LLM model name
            provider: LLM provider (ollama, openai)
            base_url: LLM API base URL
            api_key: API key for OpenAI/etc
            persist_vectors: Whether to persist vector store
            vector_dir: Directory for vector store
            temperature: LLM temperature (lower = more deterministic)
        """
        self.config = LLMConfig(
            provider=provider,
            model=model,
            base_url=base_url,
            api_key=api_key,
            temperature=temperature,
        )
        
        self._llm: BaseLLMClient | None = None
        self._vector_store: VectorStore | None = None
        self._uac_output: UACOutput | None = None
        self._chunks: list[DocumentChunk] = []
        
        # Vector store config
        self._persist_vectors = persist_vectors
        self._vector_dir = Path(vector_dir) if vector_dir else Path.home() / ".uac-ai" / "vectors"
        
        # Analysis results cache
        self._anomaly_report: AnomalyReport | None = None
        
    def _ensure_llm(self) -> BaseLLMClient:
        """Ensure LLM client is initialized."""
        if self._llm is None:
            self._llm = LLMClient.create(self.config)
            
            if not self._llm.is_available():
                raise RuntimeError(
                    f"LLM service not available at {self.config.base_url}. "
                    f"Please ensure {self.config.provider} is running."
                )
        
        return self._llm
    
    def _ensure_vector_store(self) -> VectorStore:
        """Ensure vector store is initialized."""
        if self._vector_store is None:
            persist_dir = self._vector_dir if self._persist_vectors else None
            self._vector_store = VectorStore(persist_dir=persist_dir)
        
        return self._vector_store
    
    def load_artifacts(self, uac_output: UACOutput) -> int:
        """
        Load UAC artifacts into the analyzer.
        
        Preprocesses artifacts and loads them into the vector store
        for RAG-based retrieval.
        
        Args:
            uac_output: Parsed UAC output
            
        Returns:
            Number of document chunks created
        """
        logger.info(f"Loading artifacts from {uac_output.source_file}")
        
        self._uac_output = uac_output
        
        # Preprocess into chunks
        preprocessor = Preprocessor(
            chunk_size=2000,
            chunk_overlap=200,
        )
        self._chunks = preprocessor.process(uac_output)
        
        # Load into vector store
        vector_store = self._ensure_vector_store()
        vector_store.clear()  # Clear previous data
        num_added = vector_store.add_documents(self._chunks)
        
        logger.info(f"Loaded {num_added} document chunks into vector store")
        return num_added
    
    def query(
        self,
        question: str,
        include_evidence: bool = True,
        max_context_tokens: int = 4000,
    ) -> QueryResult:
        """
        Query the forensic data with natural language.
        
        Args:
            question: Natural language question
            include_evidence: Whether to include supporting evidence
            max_context_tokens: Max tokens for context
            
        Returns:
            QueryResult with answer and evidence
        """
        logger.info(f"Processing query: {question[:50]}...")
        start_time = datetime.now()
        
        llm = self._ensure_llm()
        vector_store = self._ensure_vector_store()
        
        # Retrieve relevant context
        context = vector_store.get_context_for_query(question, max_context_tokens)
        
        # Format prompt
        prompt_template = PromptLibrary.QUERY_RESPONSE
        prompt = prompt_template.format(
            query=question,
            context=context,
        )
        
        # Generate response
        response = llm.generate(
            prompt=prompt,
            system_prompt=PromptLibrary.SYSTEM_PROMPT,
        )
        
        # Build result
        result = QueryResult(
            query=question,
            answer=response.content,
            confidence=0.7,  # TODO: Extract from response
            tokens_used=response.tokens_used,
            model_used=self.config.model,
            query_time_seconds=(datetime.now() - start_time).total_seconds(),
        )
        
        # Add evidence if requested
        if include_evidence:
            search_results = vector_store.search(question, top_k=5)
            for doc, metadata, score in search_results:
                result.evidence.append(Evidence(
                    artifact_type=metadata.get("artifact_type", "unknown"),
                    artifact_path=metadata.get("source"),
                    raw_data=doc[:500],
                    relevance_score=score,
                ))
        
        # Suggest follow-up queries
        result.suggested_queries = self._suggest_followup_queries(question)
        
        return result
    
    def query_stream(
        self,
        question: str,
        max_context_tokens: int = 4000,
    ) -> Iterator[str]:
        """
        Query with streaming response.
        
        Args:
            question: Natural language question
            max_context_tokens: Max tokens for context
            
        Yields:
            Response tokens as they're generated
        """
        llm = self._ensure_llm()
        vector_store = self._ensure_vector_store()
        
        context = vector_store.get_context_for_query(question, max_context_tokens)
        
        prompt_template = PromptLibrary.QUERY_RESPONSE
        prompt = prompt_template.format(
            query=question,
            context=context,
        )
        
        yield from llm.generate_stream(
            prompt=prompt,
            system_prompt=PromptLibrary.SYSTEM_PROMPT,
        )
    
    def detect_anomalies(
        self,
        severity_threshold: AnomalySeverity = AnomalySeverity.LOW,
    ) -> AnomalyReport:
        """
        Detect anomalies in the loaded artifacts.
        
        Args:
            severity_threshold: Minimum severity to include
            
        Returns:
            AnomalyReport with all detected anomalies
        """
        logger.info("Starting anomaly detection...")
        start_time = datetime.now()
        
        if not self._uac_output:
            raise RuntimeError("No artifacts loaded. Call load_artifacts() first.")
        
        llm = self._ensure_llm()
        anomalies: list[Anomaly] = []
        
        # Analyze different artifact types
        anomalies.extend(self._analyze_processes())
        anomalies.extend(self._analyze_network())
        anomalies.extend(self._analyze_filesystem())
        anomalies.extend(self._analyze_users())
        
        # Filter by severity threshold
        severity_order = [
            AnomalySeverity.INFO,
            AnomalySeverity.LOW,
            AnomalySeverity.MEDIUM,
            AnomalySeverity.HIGH,
            AnomalySeverity.CRITICAL,
        ]
        threshold_idx = severity_order.index(severity_threshold)
        filtered = [
            a for a in anomalies 
            if severity_order.index(a.severity) >= threshold_idx
        ]
        
        # Create report
        report = AnomalyReport(
            report_id=str(uuid.uuid4())[:8],
            generated_at=datetime.now(),
            source_file=self._uac_output.source_file,
            hostname=self._uac_output.hostname,
            anomalies=sorted(filtered, key=lambda a: (
                -severity_order.index(a.severity),
                -a.score
            )),
            total_artifacts_analyzed=len(self._chunks),
            analysis_duration_seconds=(datetime.now() - start_time).total_seconds(),
            model_used=self.config.model,
        )
        
        self._anomaly_report = report
        logger.info(f"Detected {len(report.anomalies)} anomalies")
        
        return report
    
    def _analyze_processes(self) -> list[Anomaly]:
        """Analyze processes for anomalies."""
        anomalies = []
        
        if not self._uac_output or not self._uac_output.live_response:
            return anomalies
        
        processes = self._uac_output.live_response.processes
        
        for proc in processes:
            # Check for suspicious locations
            suspicious_paths = ["/tmp/", "/var/tmp/", "/dev/shm/", "/dev/mqueue/"]
            if proc.command and any(p in proc.command for p in suspicious_paths):
                anomalies.append(Anomaly(
                    anomaly_id=f"proc_{proc.pid}_suspicious_path",
                    anomaly_type=AnomalyType.SUSPICIOUS_PROCESS,
                    severity=AnomalySeverity.HIGH,
                    score=0.8,
                    title=f"Process running from suspicious location",
                    description=f"Process PID {proc.pid} is running from a temporary or suspicious directory",
                    source_artifact="process_list",
                    evidence=[Evidence(
                        artifact_type="process",
                        raw_data=f"PID: {proc.pid}, User: {proc.user}, Command: {proc.command}",
                        explanation="Legitimate processes rarely run from /tmp or similar directories",
                    )],
                    process_name=proc.executable_name,
                    username=proc.user,
                    investigation_steps=[
                        f"Check if binary exists: ls -la {proc.command.split()[0]}",
                        f"Check process tree: pstree -p {proc.pid}",
                        f"Check open files: lsof -p {proc.pid}",
                    ],
                ))
            
            # Check for known suspicious process names
            suspicious_names = [
                "nc", "ncat", "netcat", "socat",
                "meterpreter", "beacon", "cobalt",
                "mimikatz", "lazagne", "linpeas",
            ]
            if proc.executable_name.lower() in suspicious_names:
                anomalies.append(Anomaly(
                    anomaly_id=f"proc_{proc.pid}_known_suspicious",
                    anomaly_type=AnomalyType.SUSPICIOUS_PROCESS,
                    severity=AnomalySeverity.CRITICAL,
                    score=0.95,
                    title=f"Known suspicious tool detected: {proc.executable_name}",
                    description=f"Process {proc.executable_name} is commonly used in attacks",
                    source_artifact="process_list",
                    process_name=proc.executable_name,
                    username=proc.user,
                    mitre_technique="T1059",
                ))
            
            # Check for base64/encoding in command line
            if proc.command and any(
                x in proc.command.lower() 
                for x in ["base64", "| bash", "| sh", "eval ", "exec("]
            ):
                anomalies.append(Anomaly(
                    anomaly_id=f"proc_{proc.pid}_encoded_cmd",
                    anomaly_type=AnomalyType.SUSPICIOUS_PROCESS,
                    severity=AnomalySeverity.HIGH,
                    score=0.85,
                    title="Process with potential encoded/obfuscated command",
                    description=f"Command line contains encoding or shell execution patterns",
                    source_artifact="process_list",
                    evidence=[Evidence(
                        artifact_type="process",
                        raw_data=proc.command[:200],
                        explanation="Attackers often encode commands to evade detection",
                    )],
                    process_name=proc.executable_name,
                ))
        
        return anomalies
    
    def _analyze_network(self) -> list[Anomaly]:
        """Analyze network connections for anomalies."""
        anomalies = []
        
        if not self._uac_output or not self._uac_output.live_response:
            return anomalies
        
        connections = self._uac_output.live_response.network_connections
        
        # Suspicious ports commonly used by malware
        suspicious_ports = {
            4444: "Metasploit default",
            5555: "Common backdoor",
            6666: "IRC/Backdoor",
            6667: "IRC",
            8080: "Alternative HTTP",
            31337: "Elite/Backdoor",
        }
        
        for conn in connections:
            # Check suspicious remote ports
            if conn.remote_port and conn.remote_port in suspicious_ports:
                anomalies.append(Anomaly(
                    anomaly_id=f"net_{conn.local_port}_{conn.remote_port}",
                    anomaly_type=AnomalyType.UNUSUAL_NETWORK,
                    severity=AnomalySeverity.HIGH,
                    score=0.85,
                    title=f"Connection to suspicious port {conn.remote_port}",
                    description=f"Connection to port {conn.remote_port} ({suspicious_ports[conn.remote_port]})",
                    source_artifact="network_connections",
                    evidence=[Evidence(
                        artifact_type="network",
                        raw_data=f"{conn.protocol} {conn.local_address}:{conn.local_port} -> {conn.remote_address}:{conn.remote_port}",
                    )],
                    mitre_technique="T1571",
                ))
            
            # Check suspicious listening services
            if conn.is_listening and conn.local_port in suspicious_ports:
                anomalies.append(Anomaly(
                    anomaly_id=f"net_listen_{conn.local_port}",
                    anomaly_type=AnomalyType.PERSISTENCE_MECHANISM,
                    severity=AnomalySeverity.CRITICAL,
                    score=0.9,
                    title=f"Suspicious service listening on port {conn.local_port}",
                    description=f"Service listening on known malicious port",
                    source_artifact="network_connections",
                    process_name=conn.program,
                ))
        
        return anomalies
    
    def _analyze_filesystem(self) -> list[Anomaly]:
        """Analyze filesystem artifacts for anomalies."""
        anomalies = []
        
        if not self._uac_output or not self._uac_output.bodyfile:
            return anomalies
        
        bodyfile = self._uac_output.bodyfile
        
        # Check for suspicious SUID files
        system_suid = [
            "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
            "/usr/bin/ping", "/usr/bin/mount", "/usr/bin/umount",
        ]
        
        for entry in bodyfile.setuid_files:
            if entry.name not in system_suid:
                # Non-standard SUID file
                anomalies.append(Anomaly(
                    anomaly_id=f"fs_suid_{entry.inode}",
                    anomaly_type=AnomalyType.PRIVILEGE_ESCALATION,
                    severity=AnomalySeverity.HIGH,
                    score=0.8,
                    title=f"Non-standard SUID binary: {entry.filename}",
                    description=f"SUID binary found at unexpected location: {entry.name}",
                    source_artifact="bodyfile",
                    artifact_path=entry.name,
                    timestamp=entry.mtime_dt,
                    evidence=[Evidence(
                        artifact_type="file",
                        artifact_path=entry.name,
                        raw_data=f"Mode: {entry.mode}, Size: {entry.size}, Owner: {entry.uid}",
                    )],
                    mitre_technique="T1548.001",
                    investigation_steps=[
                        f"Check file: ls -la {entry.name}",
                        f"Check file type: file {entry.name}",
                        f"Check strings: strings {entry.name} | head -50",
                    ],
                ))
        
        # Check for executables in /tmp
        for entry in bodyfile.executables:
            if any(p in entry.name for p in ["/tmp/", "/var/tmp/", "/dev/shm/"]):
                anomalies.append(Anomaly(
                    anomaly_id=f"fs_tmpexec_{entry.inode}",
                    anomaly_type=AnomalyType.SUSPICIOUS_PROCESS,
                    severity=AnomalySeverity.MEDIUM,
                    score=0.7,
                    title=f"Executable in temporary directory",
                    description=f"Executable found in world-writable directory",
                    source_artifact="bodyfile",
                    artifact_path=entry.name,
                    timestamp=entry.mtime_dt,
                ))
        
        # Check for hidden files in unexpected locations
        suspicious_hidden = [
            e for e in bodyfile.entries
            if "/." in e.name 
            and not any(x in e.name for x in [".git", ".ssh", ".config", ".local", ".cache"])
            and e.is_executable
        ]
        
        for entry in suspicious_hidden[:10]:  # Limit to avoid noise
            anomalies.append(Anomaly(
                anomaly_id=f"fs_hidden_{entry.inode}",
                anomaly_type=AnomalyType.HIDDEN_FILE,
                severity=AnomalySeverity.MEDIUM,
                score=0.6,
                title=f"Hidden executable: {entry.filename}",
                description=f"Hidden executable file found at {entry.name}",
                source_artifact="bodyfile",
                artifact_path=entry.name,
            ))
        
        return anomalies
    
    def _analyze_users(self) -> list[Anomaly]:
        """Analyze user accounts for anomalies."""
        anomalies = []
        
        if not self._uac_output or not self._uac_output.live_response:
            return anomalies
        
        users = self._uac_output.live_response.users
        
        for user in users:
            # System user with shell
            if user.is_system_user and user.has_valid_shell and user.uid not in [0]:
                anomalies.append(Anomaly(
                    anomaly_id=f"user_{user.username}_system_shell",
                    anomaly_type=AnomalyType.SUSPICIOUS_USER,
                    severity=AnomalySeverity.MEDIUM,
                    score=0.6,
                    title=f"System account with login shell: {user.username}",
                    description=f"System user {user.username} (UID {user.uid}) has a valid login shell",
                    source_artifact="passwd",
                    username=user.username,
                ))
            
            # UID 0 users other than root
            if user.uid == 0 and user.username != "root":
                anomalies.append(Anomaly(
                    anomaly_id=f"user_{user.username}_uid0",
                    anomaly_type=AnomalyType.PRIVILEGE_ESCALATION,
                    severity=AnomalySeverity.CRITICAL,
                    score=0.95,
                    title=f"Non-root user with UID 0: {user.username}",
                    description=f"User {user.username} has UID 0, equivalent to root privileges",
                    source_artifact="passwd",
                    username=user.username,
                    mitre_technique="T1136",
                ))
        
        return anomalies
    
    def _suggest_followup_queries(self, original_query: str) -> list[str]:
        """Suggest follow-up queries based on the original."""
        suggestions = []
        
        query_lower = original_query.lower()
        
        if "ssh" in query_lower:
            suggestions.extend([
                "Show failed SSH login attempts",
                "What SSH keys are authorized on the system?",
                "Are there any unusual SSH configurations?",
            ])
        elif "process" in query_lower or "pid" in query_lower:
            suggestions.extend([
                "What network connections are associated with this process?",
                "Show the process tree for suspicious processes",
                "What files were modified by running processes?",
            ])
        elif "network" in query_lower or "connection" in query_lower:
            suggestions.extend([
                "What processes are making external connections?",
                "Show all listening services",
                "Are there connections to known malicious IPs?",
            ])
        else:
            suggestions.extend([
                "What are the most suspicious findings?",
                "Show timeline of recent file modifications",
                "What persistence mechanisms might be present?",
            ])
        
        return suggestions[:3]
    
    def generate_summary(self) -> IncidentSummary:
        """
        Generate an AI-powered incident summary.
        
        Returns:
            IncidentSummary with executive summary and findings
        """
        logger.info("Generating incident summary...")
        
        if not self._uac_output:
            raise RuntimeError("No artifacts loaded. Call load_artifacts() first.")
        
        llm = self._ensure_llm()
        vector_store = self._ensure_vector_store()
        
        # Gather analysis results
        if not self._anomaly_report:
            self.detect_anomalies()
        
        # Get high-level context
        context = vector_store.get_context_for_query(
            "system overview security incidents suspicious activity",
            max_tokens=3000,
        )
        
        # Format anomalies for prompt
        anomaly_text = ""
        if self._anomaly_report:
            for anomaly in self._anomaly_report.anomalies[:20]:
                anomaly_text += f"- [{anomaly.severity.value}] {anomaly.title}\n"
        
        # Generate summary using LLM
        prompt_template = PromptLibrary.INCIDENT_SUMMARY
        prompt = prompt_template.format(
            analysis_results=context,
            anomalies=anomaly_text or "No significant anomalies detected",
            iocs="See anomaly details for IOCs",
        )
        
        response = llm.generate(
            prompt=prompt,
            system_prompt=PromptLibrary.SYSTEM_PROMPT,
        )
        
        # Parse response into structured summary
        summary = IncidentSummary(
            title=f"Forensic Analysis: {self._uac_output.hostname or 'Unknown Host'}",
            executive_summary=self._extract_section(response.content, "Executive Summary"),
            incident_start=self._uac_output.collection_time,
            affected_hosts=[self._uac_output.hostname] if self._uac_output.hostname else [],
            confidence_level="medium",
        )
        
        # Add immediate actions from response
        actions_text = self._extract_section(response.content, "Immediate")
        if actions_text:
            summary.immediate_actions = [
                line.strip().lstrip("0123456789.-) ")
                for line in actions_text.split("\n")
                if line.strip() and not line.strip().startswith("#")
            ]
        
        return summary
    
    def _extract_section(self, text: str, section_name: str) -> str:
        """Extract a section from the LLM response."""
        lines = text.split("\n")
        in_section = False
        section_lines = []
        
        for line in lines:
            if section_name.lower() in line.lower() and "#" in line:
                in_section = True
                continue
            elif in_section:
                if line.startswith("#"):
                    break
                section_lines.append(line)
        
        return "\n".join(section_lines).strip()
    
    def close(self) -> None:
        """Clean up resources."""
        if self._llm and hasattr(self._llm, "close"):
            self._llm.close()
