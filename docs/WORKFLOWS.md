# UAC AI Parser - Example Workflows

This document provides example workflows for common DFIR scenarios using the UAC AI Parser.

## Table of Contents

1. [Basic Analysis Workflow](#basic-analysis-workflow)
2. [Incident Response Workflow](#incident-response-workflow)
3. [Timeline Analysis](#timeline-analysis)
4. [Interactive Query Session](#interactive-query-session)
5. [Batch Processing](#batch-processing)
6. [Integration with Other Tools](#integration-with-other-tools)

---

## Basic Analysis Workflow

### Step 1: Parse UAC Output

```bash
# Parse a UAC tar.gz file
uac-ai parse /path/to/uac-hostname-linux-20231209.tar.gz

# Parse with JSON output
uac-ai parse /path/to/uac-output.tar.gz --json > parsed_output.json

# Parse to specific output directory
uac-ai parse /path/to/uac-output.tar.gz --output-dir ./analysis/
```

### Step 2: Run AI Analysis

```bash
# Run full AI analysis
uac-ai analyze /path/to/uac-output.tar.gz

# Analyze with specific model
uac-ai analyze /path/to/uac-output.tar.gz --model llama3:70b

# Analyze with OpenAI
uac-ai analyze /path/to/uac-output.tar.gz --provider openai --model gpt-4-turbo
```

### Step 3: Query Specific Information

```bash
# Ask specific questions
uac-ai query /path/to/uac-output.tar.gz "What processes are running as root?"
uac-ai query /path/to/uac-output.tar.gz "Are there any suspicious network connections?"
uac-ai query /path/to/uac-output.tar.gz "Show me files modified in the last 24 hours"
```

---

## Incident Response Workflow

For a suspected compromise, follow this workflow:

### 1. Initial Triage

```bash
# Quick parse to see what we have
uac-ai parse /evidence/uac-compromised-host.tar.gz --summary

# Run anomaly detection
uac-ai analyze /evidence/uac-compromised-host.tar.gz --focus anomalies
```

### 2. IOC Extraction

```bash
# Extract indicators of compromise
uac-ai analyze /evidence/uac-compromised-host.tar.gz --extract-iocs

# Export IOCs in STIX format
uac-ai analyze /evidence/uac-compromised-host.tar.gz --extract-iocs --format stix > iocs.json
```

### 3. Detailed Investigation

```bash
# Investigate specific findings
uac-ai query /evidence/uac-compromised-host.tar.gz "What happened around 2023-12-09 10:00?"
uac-ai query /evidence/uac-compromised-host.tar.gz "Show connections to IP 10.10.10.10"
uac-ai query /evidence/uac-compromised-host.tar.gz "What processes were started by user 'hacker'?"
```

### 4. Generate Incident Report

```bash
# Generate comprehensive incident summary
uac-ai analyze /evidence/uac-compromised-host.tar.gz --report > incident_report.md
```

---

## Timeline Analysis

### Generate Super Timeline with Plaso

```bash
# Generate Plaso timeline (requires Docker)
uac-ai timeline /path/to/uac-output.tar.gz --plaso

# Generate timeline for specific time range
uac-ai timeline /path/to/uac-output.tar.gz \
    --start "2023-12-09 00:00:00" \
    --end "2023-12-09 23:59:59"
```

### Analyze Timeline with AI

```bash
# Let AI analyze the timeline
uac-ai timeline /path/to/uac-output.tar.gz --analyze

# Focus on specific event types
uac-ai timeline /path/to/uac-output.tar.gz --analyze --focus authentication
```

### Example Timeline Queries

```bash
uac-ai query /path/to/uac-output.tar.gz "Reconstruct the attack timeline"
uac-ai query /path/to/uac-output.tar.gz "What was the first malicious activity?"
uac-ai query /path/to/uac-output.tar.gz "Show me persistence mechanisms installed"
```

---

## Interactive Query Session

Start an interactive session for detailed investigation:

```bash
# Start interactive mode
uac-ai query /path/to/uac-output.tar.gz --interactive
```

Example session:
```
UAC AI Parser - Interactive Mode
Loaded: uac-webserver-linux-20231209.tar.gz
Host: webserver | OS: Linux | Collected: 2023-12-09 15:30:00

> What services are running?
Based on the process list and service configurations:
- Apache2 (PID 1234) - Web server
- MySQL (PID 2345) - Database
- SSH (PID 100) - Remote access
- Suspicious: nc (PID 9999) - Netcat listener on port 4444

> Tell me more about the suspicious nc process
The netcat process (PID 9999) shows concerning characteristics:
- Running as www-data user
- Listening on port 4444 (common reverse shell port)
- Started at 2023-12-09 10:35:00
- Parent process: apache2 (PID 1234)

This suggests potential webshell or RCE exploitation.

> What was happening around 10:35?
Timeline around 2023-12-09 10:35:00:
- 10:30:00: Multiple POST requests to /upload.php
- 10:34:55: New file created: /var/www/html/.hidden/shell.php
- 10:35:00: nc process spawned by apache2
- 10:35:05: Outbound connection to 10.10.10.10:4444

> exit
```

---

## Batch Processing

Process multiple UAC collections:

```bash
# Process all UAC files in a directory
for f in /evidence/uac-*.tar.gz; do
    uac-ai analyze "$f" --json > "$(basename "$f" .tar.gz)_analysis.json"
done

# Using xargs for parallel processing
ls /evidence/uac-*.tar.gz | xargs -P 4 -I {} uac-ai analyze {} --json
```

### Aggregate Results

```python
#!/usr/bin/env python3
"""Aggregate analysis results from multiple hosts."""

import json
from pathlib import Path

results = []
for f in Path("./results").glob("*_analysis.json"):
    with open(f) as fp:
        results.append(json.load(fp))

# Find common IOCs across hosts
all_iocs = {}
for r in results:
    for ioc in r.get("iocs", []):
        key = (ioc["type"], ioc["value"])
        if key not in all_iocs:
            all_iocs[key] = []
        all_iocs[key].append(r["hostname"])

# IOCs found on multiple hosts
common_iocs = {k: v for k, v in all_iocs.items() if len(v) > 1}
print("IOCs found on multiple hosts:")
for (ioc_type, value), hosts in common_iocs.items():
    print(f"  {ioc_type}: {value} -> {hosts}")
```

---

## Integration with Other Tools

### Export to Timesketch

```bash
# Generate timeline in Timesketch format
uac-ai timeline /path/to/uac-output.tar.gz --format timesketch > timeline.jsonl

# Upload to Timesketch
timesketch_importer --host https://timesketch.local --timeline timeline.jsonl
```

### Export to Splunk

```bash
# Generate events in Splunk HEC format
uac-ai parse /path/to/uac-output.tar.gz --format splunk-hec | \
    curl -X POST https://splunk:8088/services/collector/event \
         -H "Authorization: Splunk YOUR-HEC-TOKEN" \
         -d @-
```

### Integration with MISP

```bash
# Extract IOCs and push to MISP
uac-ai analyze /path/to/uac-output.tar.gz --extract-iocs --format misp | \
    curl -X POST https://misp.local/events/add \
         -H "Authorization: YOUR-MISP-KEY" \
         -H "Content-Type: application/json" \
         -d @-
```

### Use with Velociraptor

```bash
# If UAC was collected via Velociraptor
# Export artifacts to UAC-compatible format first, then analyze
uac-ai analyze /path/to/velociraptor-export.tar.gz --artifact-format velociraptor
```

---

## Tips and Best Practices

1. **Start with parsing** - Always parse first to verify the UAC collection is valid
2. **Use appropriate models** - Larger models give better results but are slower
3. **Ask specific questions** - Targeted queries yield better results than vague ones
4. **Verify AI findings** - Always manually verify critical findings
5. **Export results** - Use JSON output for integration with other tools
6. **Use configuration profiles** - Create profiles for different analysis scenarios

## Configuration Examples

### For Air-Gapped Environments

```yaml
# config/airgapped.yaml
llm_provider: ollama
llm_model: llama3:8b
ollama_base_url: http://localhost:11434
embedding_model: all-MiniLM-L6-v2
```

### For Maximum Accuracy

```yaml
# config/high-accuracy.yaml
llm_provider: openai
llm_model: gpt-4-turbo
temperature: 0.1
max_chunk_size: 200
```

### For Speed

```yaml
# config/fast.yaml
llm_provider: ollama
llm_model: llama3:8b
temperature: 0.3
max_chunk_size: 50
```
