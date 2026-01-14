# Contributing to UAC AI Parser

Thank you for your interest in contributing to UAC AI Parser! This document provides guidelines for contributing.

## Development Setup

### Prerequisites

- Python 3.9+
- Git
- Docker (optional, for Plaso integration)
- Ollama (optional, for local LLM testing)

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/paulpol25/uac-ai-parser.git
cd uac-ai-parser

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=uac_ai_parser --cov-report=html

# Run specific test file
pytest tests/test_parser.py

# Run tests matching pattern
pytest -k "bodyfile"

# Skip slow tests
pytest -m "not slow"
```

## Code Style

We follow PEP 8 and use the following tools:

- **Black** for code formatting
- **isort** for import sorting
- **mypy** for type checking
- **flake8** for linting

```bash
# Format code
black src/ tests/
isort src/ tests/

# Check types
mypy src/

# Lint
flake8 src/ tests/
```

## Project Structure

```
uac-ai-parser/
├── src/uac_ai_parser/
│   ├── __init__.py
│   ├── cli.py              # CLI commands
│   ├── config.py           # Configuration
│   ├── models/             # Data models
│   │   ├── artifacts.py    # UAC artifact models
│   │   └── analysis.py     # Analysis result models
│   ├── core/               # Core parsing logic
│   │   ├── extractor.py    # Archive extraction
│   │   ├── parser.py       # Main parser
│   │   └── preprocessor.py # LLM preprocessing
│   ├── ai/                 # AI/LLM components
│   │   ├── llm.py          # LLM client
│   │   ├── vectorstore.py  # ChromaDB integration
│   │   ├── analyzer.py     # Analysis orchestrator
│   │   └── prompts.py      # Prompt templates
│   └── integrations/       # External integrations
│       └── plaso.py        # Plaso integration
├── tests/                  # Test suite
├── config/                 # Configuration profiles
└── docs/                   # Documentation
```

## Adding New Features

### Adding a New Artifact Type

1. Define the model in `src/uac_ai_parser/models/artifacts.py`:

```python
@dataclass
class NewArtifact:
    """New artifact type."""
    field1: str
    field2: int
    # ...
```

2. Add parsing logic in `src/uac_ai_parser/core/parser.py`:

```python
def parse_new_artifact(self, artifact_path: Path) -> List[NewArtifact]:
    """Parse new artifact type."""
    # Implementation
```

3. Add preprocessing in `src/uac_ai_parser/core/preprocessor.py`:

```python
def _process_new_artifact(self, artifacts: List[NewArtifact]) -> List[Document]:
    """Convert new artifacts to documents."""
    # Implementation
```

4. Add tests in `tests/test_new_artifact.py`

### Adding a New LLM Provider

1. Add provider logic in `src/uac_ai_parser/ai/llm.py`:

```python
def _create_new_provider(self) -> BaseLLM:
    """Create new provider instance."""
    # Implementation
```

2. Update configuration in `src/uac_ai_parser/config.py`

3. Add tests for the new provider

### Adding a New CLI Command

1. Add command in `src/uac_ai_parser/cli.py`:

```python
@cli.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--option", help="Description")
def new_command(input_file: str, option: str):
    """Command description."""
    # Implementation
```

2. Add tests in `tests/test_cli.py`

## Testing Guidelines

### Test Categories

- **Unit Tests**: Test individual functions and methods
- **Integration Tests**: Test component interactions
- **E2E Tests**: Test complete workflows (marked with `@pytest.mark.slow`)

### Test Fixtures

Common fixtures are defined in `tests/conftest.py`:

```python
@pytest.fixture
def sample_bodyfile(tmp_path):
    """Create sample bodyfile for testing."""
    # ...

@pytest.fixture
def sample_uac_output():
    """Create sample UACOutput for testing."""
    # ...
```

### Mocking External Services

Always mock external services (LLM, Docker) in unit tests:

```python
@patch("uac_ai_parser.ai.llm.ChatOllama")
def test_with_mocked_llm(mock_ollama):
    mock_ollama.return_value.invoke.return_value = Mock(content="response")
    # Test code
```

## Documentation

- Update docstrings for all public functions/classes
- Update README.md for user-facing changes
- Update WORKFLOWS.md for new usage patterns
- Add inline comments for complex logic

## Pull Request Process

1. Create a feature branch from `main`
2. Make your changes with tests
3. Ensure all tests pass: `pytest`
4. Ensure code is formatted: `black src/ tests/ && isort src/ tests/`
5. Update documentation as needed
6. Submit PR with clear description

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Code formatted with black/isort
- [ ] Type hints added
- [ ] No linting errors

## Reporting Issues

When reporting issues, please include:

- Python version
- Operating system
- UAC version (if known)
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs/error messages


## License

By contributing, you agree that your contributions will be licensed under the MIT License.
