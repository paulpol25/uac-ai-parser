# UAC AI Parser 🔍🤖

An AI-powered parser for [UAC (Unix-like Artifacts Collector)](https://github.com/tclahr/uac) outputs that combines traditional forensic analysis with LLM-based semantic analysis for enhanced incident response.

## Features

- **🗜️ Smart Extraction**: Automatically parse UAC tar.gz/zip outputs respecting volatility order
- **📊 Bodyfile Analysis**: Parse TSK-compatible bodyfiles with file metadata and hash analysis
- **⏱️ Timeline Generation**: Integration with Plaso for super timelines + AI-powered timeline analysis
- **🤖 AI-Powered Analysis**: Local LLM support via Ollama with RAG for contextual insights
- **🔍 Anomaly Detection**: AI-driven anomaly scoring for suspicious artifacts
- **💬 Interactive Queries**: Natural language queries against forensic data
- **📈 Visualizations**: Timeline visualizations with Plotly
- **📤 Export Options**: JSONL for Timesketch, Markdown reports, custom SIEM formats

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        UAC AI Parser                                │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐   ┌──────────────┐   ┌──────────────────────────┐ │
│  │  Extractor  │──▶│ Preprocessor │──▶│    Structured JSON       │ │
│  │  (tar.gz)   │   │  (normalize) │   │  (LLM-friendly chunks)   │ │
│  └─────────────┘   └──────────────┘   └────────────┬─────────────┘ │
│                                                     │               │
│  ┌─────────────────────────────────────────────────▼─────────────┐ │
│  │                      AI Layer                                  │ │
│  │  ┌─────────────┐   ┌───────────────┐   ┌───────────────────┐ │ │
│  │  │ Vector Store│   │  LLM (Ollama) │   │  Prompt Chains    │ │ │
│  │  │ (ChromaDB)  │◀─▶│  Llama3/etc   │◀─▶│  (DFIR-focused)   │ │ │
│  │  └─────────────┘   └───────────────┘   └───────────────────┘ │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                     │               │
│  ┌─────────────────────────────────────────────────▼─────────────┐ │
│  │                    Output Layer                                │ │
│  │  • Anomaly Reports    • Timeline Visualizations               │ │
│  │  • JSONL Export       • Markdown Reports                      │ │
│  │  • Interactive CLI    • Timesketch Integration                │ │
│  └───────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.ai/) (for local LLM support)
- Docker (optional, for Plaso integration)

### Install from source

```bash
git clone https://github.com/yourusername/uac-ai-parser.git
cd uac-ai-parser
pip install -e ".[dev]"
```

### Install Ollama and pull a model

```bash
# Install Ollama (see https://ollama.ai/)
ollama pull llama3.1

# Or use a smaller model for faster inference
ollama pull llama3.2:3b
```

## Quick Start

### Basic Parsing

```bash
# Parse a UAC output file
uac-ai parse /path/to/uac-output.tar.gz

# Parse with custom output directory
uac-ai parse /path/to/uac-output.tar.gz --output ./analysis
```

### AI-Powered Analysis

```bash
# Analyze for lateral movement indicators
uac-ai analyze /path/to/uac-output.tar.gz --query "lateral movement?"

# Check for privilege escalation artifacts
uac-ai analyze /path/to/uac-output.tar.gz --query "privilege escalation indicators"

# Get anomaly report
uac-ai analyze /path/to/uac-output.tar.gz --anomalies
```

### Interactive Mode

```bash
# Start interactive session
uac-ai interactive /path/to/uac-output.tar.gz

# Example queries in interactive mode:
> What processes were running without binary on disk?
> Show me SSH activity timeline
> Find suspicious cron jobs
> Correlate network connections with process activity
```

### Timeline Generation

```bash
# Generate super timeline using Plaso (requires Docker)
uac-ai timeline /path/to/uac-output.tar.gz --use-plaso

# Generate timeline visualization
uac-ai timeline /path/to/uac-output.tar.gz --visualize
```

### Export Options

```bash
# Export to JSONL for Timesketch
uac-ai export /path/to/uac-output.tar.gz --format jsonl --output timeline.jsonl

# Generate markdown report
uac-ai report /path/to/uac-output.tar.gz --format markdown

# Export structured analysis
uac-ai export /path/to/uac-output.tar.gz --format json --output analysis.json
```

## Configuration

Create a `~/.uac-ai/config.yaml` or use `--config` flag:

```yaml
# LLM Configuration
llm:
  provider: ollama  # ollama, openai, anthropic
  model: llama3.1
  base_url: http://localhost:11434
  temperature: 0.1
  
# Vector Store Configuration
vector_store:
  type: chroma
  persist_directory: ~/.uac-ai/chroma
  embedding_model: sentence-transformers/all-MiniLM-L6-v2

# Analysis Configuration
analysis:
  chunk_size: 2000
  chunk_overlap: 200
  max_tokens: 4096
  
# Anomaly Detection
anomaly:
  score_threshold: 0.7
  enabled_detectors:
    - deleted_binaries
    - suspicious_cron
    - hidden_processes
    - unusual_network
    - privilege_changes
    
# Plaso Integration
plaso:
  docker_image: log2timeline/plaso:latest
  timeout: 3600
  
# Output Configuration
output:
  default_format: json
  include_raw_artifacts: false
  timestamp_format: "%Y-%m-%d %H:%M:%S UTC"
```

## UAC Profile Mapping

UAC AI Parser supports custom artifact focus via YAML configs that mirror UAC profiles:

```yaml
# custom_profile.yaml
profile_name: "ransomware_triage"
focus_artifacts:
  - live_response/process
  - live_response/network
  - bodyfile/bodyfile.txt
  - hash_executables
  
ai_prompts:
  initial: "Analyze for ransomware indicators including encryption markers, ransom notes, and suspicious processes"
  
anomaly_weights:
  deleted_binaries: 0.9
  encrypted_files: 1.0
  unusual_network: 0.8
```

## API Usage

```python
from uac_ai_parser import UACParser, AIAnalyzer

# Parse UAC output
parser = UACParser("/path/to/uac-output.tar.gz")
artifacts = parser.parse()

# Access specific artifacts
bodyfile = artifacts.bodyfile
processes = artifacts.live_response.processes
network = artifacts.live_response.network

# AI Analysis
analyzer = AIAnalyzer(model="llama3.1")
analyzer.load_artifacts(artifacts)

# Query the data
result = analyzer.query("What suspicious SSH activity occurred?")
print(result.answer)
print(result.evidence)

# Get anomaly scores
anomalies = analyzer.detect_anomalies()
for anomaly in anomalies.high_confidence:
    print(f"{anomaly.type}: {anomaly.description} (score: {anomaly.score})")

# Generate timeline
timeline = analyzer.build_timeline()
timeline.to_jsonl("output.jsonl")
timeline.visualize("timeline.html")
```

## Supported UAC Artifacts

| Category | Artifacts | AI Analysis |
|----------|-----------|-------------|
| Live Response | Processes, Network, Users, System Info | ✅ |
| Bodyfile | File metadata, timestamps, hashes | ✅ |
| Logs | System logs, auth logs, application logs | ✅ |
| Configuration | System configs, cron jobs, services | ✅ |
| Hash Data | File hashes, process hashes | ✅ |
| Memory | Memory dumps (if collected) | 🔜 |

## Development

```bash
# Clone and install dev dependencies
git clone https://github.com/yourusername/uac-ai-parser.git
cd uac-ai-parser
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=uac_ai_parser

# Format code
black src tests
ruff check src tests --fix

# Type checking
mypy src
```

## Testing with Sample Data

Generate sample UAC outputs from your Kali/Proxmox setup:

```bash
# On target system
./uac -p full /tmp --output-format tar

# Parse the output
uac-ai parse /tmp/uac-hostname-*.tar.gz --verbose
```

## Roadmap

- [ ] AI improvements
- [ ] SoD like timeline generation (CSV format)
- [ ] Improvements to the Analyze functions 
- [ ] Sigma rule support

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a PR.

## License

Apache License 2.0 - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [UAC](https://github.com/tclahr/uac) - The excellent artifact collector this tool parses
- [Plaso](https://github.com/log2timeline/plaso) - For super timeline generation
- [LangChain](https://github.com/langchain-ai/langchain) - LLM orchestration
- [Ollama](https://ollama.ai/) - Local LLM inference
