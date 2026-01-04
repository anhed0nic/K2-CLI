# Contributing to Khao2

Thanks for your interest in contributing to Khao2! This document provides guidelines for contributing.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/k2-cli.git
   cd k2-cli
   ```
3. Install in development mode:
   ```bash
   pip install -e .
   ```

## Development Setup

### Requirements
- Python 3.7+
- pip

### Install Dependencies
```bash
pip install -e ".[dev]"
```

### Running Tests
```bash
pytest
```

## How to Contribute

### Reporting Bugs

Open an issue with:
- Clear description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS
- CLI output/error messages

### Suggesting Features

Open an issue with:
- Clear description of the feature
- Use case and motivation
- Any implementation ideas

### Pull Requests

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes
3. Write/update tests if applicable
4. Ensure tests pass: `pytest`
5. Commit with clear messages
6. Push and open a PR

### Code Style

- Follow PEP 8
- Use meaningful variable and function names
- Add docstrings to public functions and classes
- Keep functions focused and small

### Commit Messages

Use clear, descriptive commit messages:
- `fix: resolve token validation edge case`
- `feat: add JSON output format`
- `docs: update installation instructions`
- `refactor: simplify config loading`

## Project Structure

```
khao2/
├── core/           # Core models and exceptions
├── presentation/   # CLI and display logic
├── services/       # API client and business logic
└── utils/          # Configuration and helpers
```

## Code of Conduct

Be respectful and constructive. We're all here to build something useful.

## Questions?

Open an issue or reach out at odin@odinglynn.com.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
