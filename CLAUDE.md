# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is `bun-socket-scanner`, a Bun security scanner that integrates with Socket.dev for package vulnerability detection. The scanner implements the `Bun.Security.Scanner` interface and automatically scans npm packages during `bun install` for security issues and supply chain risks.

## Development Commands

### Core Development

- `bun test` - Run all tests using Bun's built-in test runner
- `bun run typecheck` - Run TypeScript type checking with `tsgo --noEmit`
- `bun run lint` - Run ESLint with caching
- `bun run format` - Auto-fix ESLint issues
- `bun run start` - Run the CLI interface for API key management

### Testing

- All test files are located in `src/` directory with `.test.ts` suffix
- Tests use Bun's built-in test framework (`bun:test`)
- Mock the Socket SDK using `mock.module()` for API testing

## Architecture

### Core Components

**Scanner (`src/scanner.ts`)**

- Main security scanner implementing `Bun.Security.Scanner` interface
- Integrates with Socket.dev API to check package vulnerabilities and supply chain risks
- Uses two risk thresholds: `FATAL_RISK_THRESHOLD = 0.3`, `WARN_RISK_THRESHOLD = 0.5`
- Returns advisories with `fatal` or `warn` levels based on severity

**Secrets Management (`src/secrets.ts`)**

- Handles Socket.dev API key storage using `Bun.secrets`
- Prioritizes environment variable `NI_SOCKETDEV_TOKEN` over stored secrets
- Provides secure storage/retrieval operations

**CLI Interface (`src/cli.ts`)**

- Command-line interface for API key management using `gunshi` CLI framework
- Commands: `set`, `delete`, `status` for managing Socket.dev API keys
- Entry point: `src/index.ts` (when `import.meta.main`)

**Input Utilities (`src/input.ts`)**

- Secure password input with masking for API key entry
- Handles Ctrl+C cancellation and backspace editing

### Package Structure

- **Entry point**: `src/index.ts` exports the scanner and handles CLI mode
- **Scanner interface**: Implements `Bun.Security.Scanner` with version '1'
- **Dependencies**:
  - `@socketsecurity/sdk` for Socket.dev API integration
  - `gunshi` for CLI framework
  - `consola` for logging

## Configuration Files

- **`bunfig.toml`**: Configures this package as the security scanner
- **`eslint.config.js`**: Uses `@ryoppippi/eslint-config` with TypeScript support
- **`tsconfig.json`**: TypeScript configuration with strict settings and Bun types
- **Environment**: Requires `NI_SOCKETDEV_TOKEN` environment variable or uses `Bun.secrets`

## Security Scanner Integration

The scanner is designed to be used in `bunfig.toml`:

```toml
[install.security]
scanner = "bun-socket-scanner"
```

It scans packages during installation and:

1. Queries Socket.dev API for security issues and supply chain scores
2. Categorizes risks as `fatal` (blocks install) or `warn` (prompts user)
3. Provides detailed descriptions and URLs for security reports
4. Handles API errors gracefully without blocking installations

## Testing Strategy

- Comprehensive test coverage in `src/index.test.ts` and `src/scanner.test.ts`
- Tests mock the Socket SDK to simulate various security scenarios
- Covers fatal/warning risk detection, API error handling, and multi-package scanning
- Uses environment variable mocking for API key testing
