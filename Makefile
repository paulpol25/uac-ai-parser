.PHONY: install dev-install test lint format clean build docker

# Install production dependencies
install:
	pip install -e .

# Install development dependencies
dev-install:
	pip install -e ".[dev]"
	pre-commit install

# Run tests
test:
	pytest tests/ -v

# Run tests with coverage
coverage:
	pytest tests/ --cov=uac_ai_parser --cov-report=html --cov-report=term

# Run linting
lint:
	flake8 src/ tests/
	mypy src/

# Format code
format:
	black src/ tests/
	isort src/ tests/

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Build package
build: clean
	python -m build

# Build Docker image
docker:
	docker build -t uac-ai-parser:latest .

# Run Docker compose stack
docker-up:
	docker-compose up -d

# Stop Docker compose stack
docker-down:
	docker-compose down

# Pull Ollama model
pull-model:
	ollama pull llama3

# Run a quick smoke test
smoke-test:
	uac-ai --help
	uac-ai parse --help
	uac-ai analyze --help

# Show help
help:
	@echo "Available targets:"
	@echo "  install      - Install production dependencies"
	@echo "  dev-install  - Install development dependencies"
	@echo "  test         - Run tests"
	@echo "  coverage     - Run tests with coverage"
	@echo "  lint         - Run linting"
	@echo "  format       - Format code"
	@echo "  clean        - Clean build artifacts"
	@echo "  build        - Build package"
	@echo "  docker       - Build Docker image"
	@echo "  docker-up    - Start Docker compose stack"
	@echo "  docker-down  - Stop Docker compose stack"
	@echo "  pull-model   - Pull Ollama llama3 model"
	@echo "  smoke-test   - Run quick smoke test"
