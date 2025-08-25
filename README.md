# Bun Socket Security Scanner

A security scanner for Bun that integrates with Socket.dev to detect vulnerabilities and supply chain risks in npm packages during installation.

## Features

- 🔍 **Real-time Security Scanning**: Automatically scans packages during `bun install`
- 🛡️ **Socket.dev Integration**: Leverages Socket.dev's comprehensive vulnerability database
- ⚡ **Fatal vs Warning Levels**: Categorizes security issues to either block installation or prompt user
- 🔄 **Supply Chain Risk Detection**: Evaluates packages for supply chain security risks
- 🎯 **Bun-native**: Built specifically for Bun's security scanner interface

## Installation

### 1. Install the Scanner

```bash
# Install as a dev dependency
bun add -d bun-socket-scanner

# Or install globally
bun add -g bun-socket-scanner
```

### 2. Get Socket.dev API Key

1. Visit [Socket.dev Dashboard](https://socket.dev/dashboard)
2. Create an account or sign in
3. Generate an API key with appropriate permissions

### 3. Configure Environment

Create a `.env` file or set the environment variable:

```bash
# .env file
NI_SOCKETDEV_TOKEN=your_socket_api_key_here
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

### Security Levels

- **Fatal**: Blocks installation immediately
  - Critical security issues (malware, trojans, backdoors)
  - High supply chain risk (score < 0.3)

- **Warning**: Prompts user for confirmation
  - Moderate security issues
  - Moderate supply chain risk (score 0.3-0.5)

## Development

### Testing

```bash
# Run tests
bun test

# Run with coverage
bun test --coverage
```

### Type Checking

```bash
bun run typecheck
```

### Building

```bash
bun run build
```

## API Reference

The scanner implements the `Bun.Security.Scanner` interface:

```typescript
type Scanner = {
	version: '1';
	scan: (info: { packages: Package[] }) => Promise<Advisory[]>;
};
```

### Package Interface

```typescript
type Package = {
	name: string; // Package name
	version: string; // Exact version to install
	tarball: string; // URL of package's tgz file
	requestedRange: string; // Version range or tag requested
};
```

### Advisory Interface

```typescript
type Advisory = {
	level: 'fatal' | 'warn'; // Severity level
	package: string; // Package name
	url: string | null; // Link to security report
	description: string | null; // Brief description
};
```

## Configuration Options

The scanner uses the following environment variables:

- `NI_SOCKETDEV_TOKEN`: Your Socket.dev API key (required)

## How It Works

1. **Package Detection**: When `bun install` runs, Bun calls the scanner with package information
2. **Socket.dev Query**: Scanner queries Socket.dev API for security issues and scores
3. **Risk Assessment**: Evaluates packages based on:
   - Critical security issues (malware, backdoors)
   - Supply chain risk scores
   - General security issues
4. **Decision**: Returns advisories with appropriate severity levels
5. **User Action**: Bun either blocks installation (fatal) or prompts user (warning)

## Troubleshooting

### No API Key Warning

```
NI_SOCKETDEV_TOKEN not found, skipping security scan
```

**Solution**: Set the `NI_SOCKETDEV_TOKEN` environment variable.

### API Errors

The scanner handles API errors gracefully and won't block installations due to network issues.

### Rate Limits

Socket.dev has API rate limits. The scanner respects these and will warn about quota issues.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `bun test`
5. Submit a pull request

## License

MIT

## Related Projects

- [Bun](https://bun.com) - Fast all-in-one JavaScript runtime
- [Socket.dev](https://socket.dev) - Supply chain security platform
- [Security Scanner Template](https://github.com/oven-sh/security-scanner-template) - Official Bun scanner template
