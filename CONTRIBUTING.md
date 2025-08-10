# Contributing to Microsoft Purview Security Analyzer

Thank you for your interest in contributing to the Microsoft Purview Security Analyzer! This document provides guidelines for contributing to the project.

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Basic knowledge of Streamlit, Pandas, and Python

### Development Setup

1. **Fork the repository** on GitHub
2. **Clone your fork locally**:
```bash
git clone https://github.com/umarcybr/microsoft-purview-security-analyzer.git
cd microsoft-purview-security-analyzer
```
3. **Create a virtual environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
4. **Install dependencies**:
```bash
pip install streamlit pandas folium streamlit-folium geoip2 openpyxl trafilatura
```
5. **Download the GeoLite2 database** (see INSTALLATION.md)

## How to Contribute

### Reporting Bugs

1. **Check existing issues** to avoid duplicates
2. **Create a detailed bug report** including:
   - Description of the problem
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Python version, etc.)
   - Sample data files (if applicable and safe to share)

### Suggesting Features

1. **Open an issue** with the "enhancement" label
2. **Describe the feature** in detail:
   - Use case and benefits
   - Proposed implementation approach
   - Any potential drawbacks or considerations

### Code Contributions

#### 1. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
```

#### 2. Make Your Changes

**Code Style Guidelines:**
- Follow PEP 8 Python style guidelines
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and modular

**File Organization:**
- `app_new.py`: Main Streamlit application
- `security_analyzer.py`: Core analysis functions
- Add new modules for substantial new features

#### 3. Test Your Changes
- Test with various file formats (CSV, Excel)
- Verify the interactive map functionality
- Check error handling with invalid data
- Ensure the dark theme works correctly

#### 4. Commit Your Changes
```bash
git add .
git commit -m "Add feature: descriptive commit message"
```

**Commit Message Guidelines:**
- Use present tense ("Add feature" not "Added feature")
- Keep the first line under 50 characters
- Add detailed description if needed after a blank line

#### 5. Push and Create Pull Request
```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub with:
- Clear title and description
- Reference any related issues
- Describe what you've changed and why

## Code Areas Needing Help

### High Priority
- **Performance optimization** for large datasets
- **Additional file format support** (JSON, XML)
- **Enhanced anomaly detection** algorithms
- **Export options** (PDF reports, Excel)

### Medium Priority
- **User interface improvements**
- **Additional visualizations**
- **Configuration options**
- **Logging and debugging tools**

### Low Priority
- **Internationalization** (multiple languages)
- **Plugin system** for custom analyzers
- **API integration** with security tools

## Development Guidelines

### Security Considerations
- Never commit sensitive data or API keys
- Validate all user inputs
- Use secure file handling practices
- Follow OWASP guidelines for web applications

### Performance Best Practices
- Cache expensive operations when possible
- Use vectorized operations with Pandas
- Optimize database queries
- Handle large files efficiently

### UI/UX Guidelines
- Maintain the dark theme consistency
- Provide clear error messages
- Add progress indicators for long operations
- Ensure responsive design

## Testing

### Manual Testing Checklist
- [ ] File upload with various formats
- [ ] Map interaction and zooming
- [ ] Data table filtering and sorting
- [ ] Export functionality
- [ ] Error handling with invalid files
- [ ] Performance with large datasets

### Automated Testing (Future)
We're planning to add automated tests. Contributions in this area are welcome!

## Documentation

When contributing, please:
- Update README.md if changing functionality
- Add docstrings to new functions
- Update INSTALLATION.md for new dependencies
- Create examples for new features

## Release Process

Maintainers will:
1. Review pull requests
2. Test thoroughly
3. Merge approved changes
4. Create release tags
5. Update documentation

## Questions and Support

- **GitHub Issues**: For bug reports and feature requests
- **Discussions**: For questions and general discussion
- **Email**: For security concerns or private matters

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be acknowledged in:
- README.md contributors section
- Release notes
- Project documentation

Thank you for helping make this tool better for the security community!