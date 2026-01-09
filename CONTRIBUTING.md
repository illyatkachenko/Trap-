# Contributing to Trap

Thank you for your interest in contributing to Trap! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/illyatkachenko/Trap-/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details (OS, Node.js version, Next.js version)

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue with the "feature request" label
3. Describe the feature and its use case

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature-name`
3. Make your changes
4. Write/update tests if applicable
5. Run linting: `npm run lint`
6. Run tests: `npm test`
7. Commit with clear messages: `git commit -m "feat: add new trap type"`
8. Push to your fork: `git push origin feature/your-feature-name`
9. Create a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Trap-.git
cd Trap-

# Install dependencies
npm install

# Start development mode
npm run dev
```

## Code Style

- Use TypeScript
- Follow existing code patterns
- Use meaningful variable and function names
- Add JSDoc comments for public APIs
- Keep functions focused and small

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `test:` - Adding or updating tests
- `chore:` - Maintenance tasks

## Testing

- Write tests for new features
- Ensure all tests pass before submitting PR
- Test with different Node.js and Next.js versions if possible

## Security

If you discover a security vulnerability, please email directly instead of creating a public issue.

## Questions?

Feel free to open an issue for any questions about contributing.

Thank you for helping make Trap better! 🪤

