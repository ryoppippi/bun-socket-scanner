import { afterEach, beforeEach, expect, test } from 'bun:test';
import { scanner } from './scanner';
import { deleteApiKey, setApiKey } from './secrets';

// Mock environment variables
const originalEnv = process.env;

beforeEach(() => {
	// Clean up environment for each test
	delete process.env.NI_SOCKETDEV_TOKEN;
	delete Bun.env.NI_SOCKETDEV_TOKEN;
});

afterEach(async () => {
	// Clean up secrets after each test
	try {
		await deleteApiKey();
	}
	catch {
		// Ignore errors if key doesn't exist
	}

	// Restore original environment
	process.env = { ...originalEnv };
});

test('scanner - no API key configured', async () => {
	// Should throw error when no API key is configured
	expect(async () => {
		await scanner.scan({
			packages: [
				{ name: 'test-package', version: '1.0.0', tarball: '', requestedRange: '1.0.0' },
			],
		});
	}).toThrow('Socket.dev API key not found. Configure with: bun run src/index.ts set or set NI_SOCKETDEV_TOKEN environment variable');
});

test('scanner - environment variable API key takes precedence', async () => {
	// Set both environment variable and secret
	process.env.NI_SOCKETDEV_TOKEN = 'env-key';
	Bun.env.NI_SOCKETDEV_TOKEN = 'env-key';
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
	process.env.NI_SOCKETDEV_TOKEN = '';
	Bun.env.NI_SOCKETDEV_TOKEN = '';
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
	process.env.NI_SOCKETDEV_TOKEN = 'test-key';
	Bun.env.NI_SOCKETDEV_TOKEN = 'test-key';

	const result = await scanner.scan({
		packages: [],
	});

	expect(result).toEqual([]);
});
