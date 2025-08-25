# Bun Socket Security Scanner

<p align="center">
<a href="https://npmjs.com/package/bun-socket-scanner"><img src="https://img.shields.io/npm/v/bun-socket-scanner?color=yellow" alt="npm version"></a>
<a href="https://npmjs.com/package/bun-socket-scanner"><img src="https://img.shields.io/npm/dy/bun-socket-scanner" alt="npm downloads"></a>
<a href="https://packagephobia.com/result?p=bun-socket-scanner"><img src="https://packagephobia.com/badge?p=bun-socket-scanner" alt="install size"></a>
<a href="https://deepwiki.com/ryoppippi/bun-socket-scanner"><img src="https://img.shields.io/badge/DeepWiki-ryoppippi%2Fbun--socket--scanner-blue.svg?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAFdSURBVHgBfVJNSwJBFH5md2dnd1dXV5fSk0dBD0oPHrt069atH9CtW7/AY5cuHTp48NelaweP0aFbB28dg24dPHjxINSBiAjCjZ15b2YJhBcG3ryZ9z7vfe87AyAi8gAHAPjKsqzM5/PtBwKBHcuyHPijLRgMDnq93gWHw7HOGGNkLpeL+Xy+puu6Q0T8JyJy4vH4TCAQ2GGM1QghghDSJoS0CCFN13U/XdcFACCENAghLUJIWwjRI4Q0hRBOOp1eHI/HL+PxeCGdTpdTqdT3YDC44HK5Vhljqm3bFcaYahjGUFGU9mAwaCuK0jYMY6gu67LjOKRer49jsdjqaDT6xvP8rCAIAgAAx3G/qqoqo6oqx3EcsyzrOwzDQqPRGMfj8aWBQGBR0zRLFEXTNE1DURQ1k8ksa5oW9fv9C7Va7apYLJaTyWRRluUFQRBUQRAUWZYXZFluJRKJq3K5fFOv1z8HxWJxJhgMzrPsP38AnwE4VJ9SAz8AAAAASUVORK5CYII=" alt="DeepWiki"></a>
<a href="https://choosealicense.com/licenses/mit/"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License"></a>
</p>

A security scanner for Bun that integrates with Socket.dev to detect vulnerabilities and supply chain risks in npm packages during installation.

<div align="center">
    <img src="https://cdn.jsdelivr.net/gh/ryoppippi/bun-socket-scanner@main/docs/screenshot.jpeg">
</div>

## Why I Built This

This project was inspired by [ni.zsh's malware detection features](https://efcl.info/2023/08/29/ni.zsh-socket.dev/) and built specifically for Bun's new [Security Scanner API](https://bun.com/blog/bun-v1.2.21#security-scanner-api-for-bun-install) introduced in v1.2.21. It integrates with [Socket.dev](https://socket.dev)'s comprehensive vulnerability database to provide real-time security scanning during package installation, helping protect applications from supply chain attacks and known vulnerabilities. The scanner categorizes security issues into fatal (blocks installation) and warning (prompts user) levels, offering the same proactive security checking that ni.zsh provides but natively integrated with Bun's package installation process.

## Installation

```bash
# First, install the scanner as a dev dependency
bun add -d bun-socket-scanner
```

### Get Socket.dev API Key

To use this scanner, you need a Socket.dev API key. Follow these steps:

1. Visit [https://socket.dev/](https://socket.dev/) and create an account
2. Create a project by installing the GitHub App to any repository (any repo works fine)
3. Navigate to your API tokens page: `https://socket.dev/dashboard/org/gh/{your-username}/settings/api-tokens`
4. Generate and copy your API token

For more details, see the [ni.zsh Socket.dev integration guide](https://efcl.info/2023/08/29/ni.zsh-socket.dev/).

### 3. Configure API Key

You can set the API key using either method:

#### Option A: Environment Variable

```bash
export BUN_SOCKET_TOKEN="your_socket_api_key_here"
```

#### Option B: CLI Tool

```bash
# Set API key securely
bunx bun-socket-scanner set

# Check current status
bunx bun-socket-scanner status

# Delete stored key
bunx bun-socket-scanner delete
```

### 4. Configure Bun

Add the scanner to your `bunfig.toml`:

```toml
[install.security]
scanner = "bun-socket-scanner"
```

## Usage

Once configured, the scanner will automatically run during `bun install`:

```bash
bun install express
# Scanner will check express and its dependencies for security issues
```

### Security Risk Levels

The scanner uses Socket.dev's risk scoring system with two thresholds:

- **Fatal (Risk Score < 0.3)**: Blocks installation immediately
  - Critical security issues (malware, trojans, backdoors)
  - Very high supply chain risk

- **Warning (Risk Score 0.3-0.5)**: Prompts user for confirmation
  - Moderate security issues
  - Moderate supply chain risk

**Note**: Complex packages (bundled, using special Unicode characters, etc.) may trigger false positives. Always verify the package legitimacy before proceeding with installation.

### CLI Commands

Manage your Socket.dev API key:

```bash
# Set API key (secure input with masking)
bunx bun-socket-scanner set

# Check API key status
bunx bun-socket-scanner status

# Delete stored API key
bunx bun-socket-scanner delete
```

API keys are securely stored using [Bun.secrets](https://bun.com/blog/bun-v1.2.21#bun-secrets-native-secrets-manager-for-cli-tools), which provides native keychain/credential manager integration.

## How It Works

1. **Package Detection**: When `bun install` runs, Bun calls the scanner with package information
2. **Socket.dev Query**: Scanner queries Socket.dev API for security issues and supply chain scores
3. **Risk Assessment**: Evaluates packages based on:
   - Critical security issues (malware, backdoors)
   - Supply chain risk scores (using 0.3 and 0.5 thresholds)
   - General security vulnerabilities
4. **Decision**: Returns advisories with appropriate severity levels
5. **User Action**: Bun either blocks installation (fatal) or prompts user (warning)

## Configuration Options

The scanner uses the following environment variables:

- `BUN_SOCKET_TOKEN`: Your Socket.dev API key (required)

### Risk Score Thresholds

The scanner uses two configurable thresholds to categorize security risks:

- `FATAL_RISK_THRESHOLD = 0.3`: Packages with risk scores below this threshold trigger fatal warnings (block installation)
- `WARN_RISK_THRESHOLD = 0.5`: Packages with risk scores between 0.3-0.5 trigger warning prompts

## Troubleshooting

### No API Key Warning

```
BUN_SOCKET_TOKEN not found, skipping security scan
```

**Solution**: Set the `BUN_SOCKET_TOKEN` environment variable or use the CLI tool.

### API Errors

The scanner handles API errors gracefully and won't block installations due to network issues.

### Rate Limits

Socket.dev has API rate limits. The scanner respects these and will warn about quota issues.

## References & Credits

### Acknowledgements

- [@alii](https://github.com/alii) - For implementing Bun's Security Scanner API
- [@azu](https://github.com/azu) - Creator of ni.zsh and its Socket.dev integration that inspired this project

### Inspired By

- [ni.zsh](https://github.com/azu/ni.zsh) - Universal package manager wrapper with supply chain security
- [ni.zsh Socket.dev integration guide](https://efcl.info/2023/08/29/ni.zsh-socket.dev/) - Japanese article about malware detection

### Built With

- [Bun Security Scanner API](https://bun.com/blog/bun-v1.2.21#security-scanner-api-for-bun-install) - Native Bun security scanning
- [Bun Security Scanner Documentation](https://bun.com/docs/runtime/bunfig#install-security-scanner) - Official documentation

## License

MIT
