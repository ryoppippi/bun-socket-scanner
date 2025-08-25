import { afterEach, beforeEach, expect, test } from 'bun:test';
import { scanner } from './scanner';
import { deleteApiKey, setApiKey } from './secrets';

// Mock environment variables - not used but kept for future compatibility

beforeEach(() => {
	// Clean up environment for each test
	delete Bun.env.BUN_SOCKET_TOKEN;
	delete Bun.env.BUN_SOCKET_SCANNER_FATAL_THRESHOLD;
	delete Bun.env.BUN_SOCKET_SCANNER_WARN_THRESHOLD;
});

afterEach(async () => {
	// Clean up secrets after each test
	try {
		await deleteApiKey();
	}
	catch {
		// Ignore errors if key doesn't exist
	}

	// Restore original environment (Bun.env is read-only, so we just clean up what we set)
});

test('scanner - no API key configured', async () => {
	// Should throw error when no API key is configured
	expect(async () => {
		await scanner.scan({
			packages: [
				{ name: 'test-package', version: '1.0.0', tarball: '', requestedRange: '1.0.0' },
			],
		});
	}).toThrow('Socket.dev API key not found. Configure with: bun run src/index.ts set or set BUN_SOCKET_TOKEN environment variable');
});

test('scanner - environment variable API key takes precedence', async () => {
	// Set both environment variable and secret
	Bun.env.BUN_SOCKET_TOKEN = 'env-key';
	await setApiKey('secret-key');

	// Mock console.warn to verify it's not called when key exists
	const originalWarn = console.warn;
	let warnCalled = false;
	console.warn = () => {
		warnCalled = true;
	};

	await scanner.scan({
		packages: [
			{ name: 'lodash', version: '4.17.21', tarball: '', requestedRange: '4.17.21' },
		],
	});

	// Should not warn about missing API key
	expect(warnCalled).toBe(false);

	console.warn = originalWarn;
});

test('scanner - uses Bun.secrets when no environment variable', async () => {
	// Only set secret, no environment variable
	await setApiKey('secret-key');

	// Mock console.warn to verify it's not called when key exists
	const originalWarn = console.warn;
	let warnCalled = false;
	console.warn = () => {
		warnCalled = true;
	};

	await scanner.scan({
		packages: [
			{ name: 'lodash', version: '4.17.21', tarball: '', requestedRange: '4.17.21' },
		],
	});

	// Should not warn about missing API key
	expect(warnCalled).toBe(false);

	console.warn = originalWarn;
});

test('scanner - empty environment variable fallback to secrets', async () => {
	// Set empty environment variable and a secret
	Bun.env.BUN_SOCKET_TOKEN = '';
	await setApiKey('secret-key');

	// Mock console.warn to verify it's not called when secret key exists
	const originalWarn = console.warn;
	let warnCalled = false;
	console.warn = () => {
		warnCalled = true;
	};

	await scanner.scan({
		packages: [
			{ name: 'lodash', version: '4.17.21', tarball: '', requestedRange: '4.17.21' },
		],
	});

	// Should not warn about missing API key
	expect(warnCalled).toBe(false);

	console.warn = originalWarn;
});

test('scanner - version property', () => {
	expect(scanner.version).toBe('1');
});

test('scanner - empty packages array', async () => {
	Bun.env.BUN_SOCKET_TOKEN = 'test-key';

	const result = await scanner.scan({
		packages: [],
	});

	expect(result).toEqual([]);
});

test('scanner - custom threshold environment variables', async () => {
	// Set custom thresholds
	Bun.env.BUN_SOCKET_SCANNER_FATAL_THRESHOLD = '0.1';
	Bun.env.BUN_SOCKET_SCANNER_WARN_THRESHOLD = '0.8';
	Bun.env.BUN_SOCKET_TOKEN = 'test-key';

	// Mock logger.warn to capture validation messages
	const { logger } = await import('./logger');
	const originalWarn = logger.warn;
	const warnMessages: string[] = [];
	logger.warn = Object.assign((...args: unknown[]) => {
		warnMessages.push(args.join(' '));
	}, { raw: (...args: unknown[]) => {
		warnMessages.push(args.join(' '));
	} });

	// Re-import scanner to pick up new environment variables
	delete require.cache[require.resolve('./scanner')];
	const { scanner: newScanner } = await import('./scanner');

	const result = await newScanner.scan({
		packages: [],
	});

	expect(result).toEqual([]);
	// Should not warn about threshold values since they are valid
	expect(warnMessages.filter(msg => msg.includes('Invalid'))).toHaveLength(0);

	logger.warn = originalWarn;
});

test('scanner - invalid threshold environment variables use defaults', async () => {
	// Set invalid thresholds
	Bun.env.BUN_SOCKET_SCANNER_FATAL_THRESHOLD = 'invalid';
	Bun.env.BUN_SOCKET_SCANNER_WARN_THRESHOLD = '2.0';
	Bun.env.BUN_SOCKET_TOKEN = 'test-key';

	// Mock logger.warn to capture validation messages
	const { logger } = await import('./logger');
	const originalWarn = logger.warn;
	const warnMessages: string[] = [];
	logger.warn = Object.assign((...args: unknown[]) => {
		warnMessages.push(args.join(' '));
	}, { raw: (...args: unknown[]) => {
		warnMessages.push(args.join(' '));
	} });

	// Re-import scanner to pick up new environment variables
	delete require.cache[require.resolve('./scanner')];
	const { scanner: newScanner } = await import('./scanner');

	const result = await newScanner.scan({
		packages: [],
	});

	expect(result).toEqual([]);
	// Should warn about invalid threshold values
	expect(warnMessages.some(msg => msg.includes('Invalid BUN_SOCKET_SCANNER_FATAL_THRESHOLD'))).toBe(true);
	expect(warnMessages.some(msg => msg.includes('Invalid BUN_SOCKET_SCANNER_WARN_THRESHOLD'))).toBe(true);

	logger.warn = originalWarn;
});
