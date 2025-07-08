# Contributing to Vulnerabililizer

Thank you for your interest in contributing to Vulnerabililizer! This document provides guidelines for contributing to the project.

## 🚀 Quick Start

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/vulnerabililizer.git
   cd vulnerabililizer
   ```
3. **Install development dependencies**:
   ```bash
   pip install uv
   uv pip install -e ".[dev]"
   ```

## 🛠 Development Setup

### Prerequisites
- Python 3.8+
- uv package manager
- Docker (for containerization testing)
- Git

### Development Environment
```bash
# Install in development mode
make install

# Run tests
make test

# Run linting
make lint

# Format code
make format

# Build Docker image
make docker-build
```

## 📝 Contributing Guidelines

### Code Style
- Follow PEP 8 Python style guidelines
- Use type hints where possible
- Write descriptive commit messages
- Add docstrings to public functions and classes

### Testing
- Write tests for new features
- Ensure all tests pass before submitting
- Maintain or improve code coverage

### Pull Request Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Write clean, well-documented code
   - Add tests for new functionality
   - Update documentation if needed

3. **Test your changes**:
   ```bash
   make test
   make lint
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "Add feature: descriptive message"
   ```

5. **Push to your fork**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create Pull Request**:
   - Go to GitHub and create a pull request
   - Provide clear description of changes
   - Reference any related issues

### Commit Message Format

Use conventional commit format:
```
type(scope): description

Examples:
feat(cli): add database query optimization
fix(database): resolve connection timeout issue
docs(readme): update installation instructions
test(models): add validation test cases
```

## 🐛 Bug Reports

When reporting bugs, include:
- Operating system and version
- Python version
- Steps to reproduce
- Expected vs actual behavior
- Error messages or logs
- Minimal code example if applicable

## 💡 Feature Requests

For feature requests, provide:
- Clear description of the feature
- Use case and motivation
- Example of how it would work
- Any relevant implementation ideas

## 📊 Database Contributions

### Adding New Data Sources
- Ensure data format compatibility
- Add appropriate schema migrations
- Update documentation
- Include sample data for testing

### Performance Improvements
- Profile before and after changes
- Include benchmarks in PR description
- Test with large datasets

## 🔧 Development Areas

We welcome contributions in these areas:

### Core Features
- Additional input format support
- Enhanced vulnerability analysis algorithms
- Performance optimizations
- Database schema improvements

### Infrastructure
- CI/CD pipeline improvements
- Docker optimizations
- Documentation enhancements
- Test coverage expansion

### Integrations
- Additional vulnerability databases
- API development
- Export format support
- Third-party tool integrations

## 📚 Documentation

### Types of Documentation
- Code documentation (docstrings)
- User guides and tutorials
- API documentation
- Database schema documentation

### Documentation Standards
- Use clear, concise language
- Include practical examples
- Keep documentation up to date
- Use Markdown for formatting

## 🏆 Recognition

Contributors will be:
- Listed in the project README
- Mentioned in release notes
- Credited in relevant documentation

## 📞 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Documentation**: Check docs/ directory for detailed guides

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 🙏 Thank You

Every contribution, no matter how small, helps make Vulnerabililizer better. We appreciate your time and effort! 