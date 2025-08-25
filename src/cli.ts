import process from 'node:process';
import { cli, define } from 'gunshi';
import { readPassword } from './input';
import { deleteApiKey, hasApiKey, setApiKey } from './secrets';

/**
 * Gets the current API key configuration status
 * @returns Object containing status information
 */
async function getApiKeyStatus(): Promise<{
	hasKey: boolean;
	source: 'environment' | 'secrets' | 'none';
}> {
	// Check environment variable first
	const envKey = Bun.env.NI_SOCKETDEV_TOKEN;
	if (envKey != null && envKey !== '') {
		return {
			hasKey: true,
			source: 'environment',
		};
	}

	// Check if key exists in Bun.secrets
	const hasSecretKey = await hasApiKey();
	if (hasSecretKey) {
		return {
			hasKey: true,
			source: 'secrets',
		};
	}

	return {
		hasKey: false,
		source: 'none',
	};
}

/**
 * Displays the current API key configuration status
 */
async function showStatus(): Promise<void> {
	const status = await getApiKeyStatus();

	console.log('Socket.dev API Key Status:');
	console.log('========================');

	if (status.hasKey) {
		console.log('✅ API key is configured');
		switch (status.source) {
			case 'environment':
				console.log('📍 Source: Environment variable (NI_SOCKETDEV_TOKEN)');
				break;
			case 'secrets':
				console.log('📍 Source: Bun.secrets (secure storage)');
				break;
			case 'none':
				// This case should not be reached when hasKey is true
				break;
		}
	}
	else {
		console.log('❌ No API key configured');
		console.log('💡 Use "bun run src/index.ts set" to configure an API key');
	}
}

// CLI Commands for API key management
const setCommand = define({
	name: 'set',
	description: 'Set the Socket.dev API key',
	run: async () => {
		try {
			const apiKey = await readPassword('Enter Socket.dev API key: ');

			if (apiKey.trim() === '') {
				console.error('❌ API key cannot be empty');
				process.exit(1);
			}

			await setApiKey(apiKey.trim());
			console.log('✅ API key has been saved securely');
		}
		catch (error) {
			if (error instanceof Error && error.message === 'User cancelled input') {
				console.log('\n⚠️  Operation cancelled');
				process.exit(0);
			}
			console.error('❌ Failed to set API key:', error);
			process.exit(1);
		}
	},
});

const deleteCommand = define({
	name: 'delete',
	description: 'Delete the stored Socket.dev API key',
	run: async () => {
		try {
			await deleteApiKey();
			console.log('✅ API key has been deleted');
		}
		catch (error) {
			console.error('❌ Failed to delete API key:', error);
			process.exit(1);
		}
	},
});

const statusCommand = define({
	name: 'status',
	description: 'Show current API key configuration status',
	run: async () => {
		await showStatus();
	},
});

const mainCommand = define({
	name: 'bun-socket-scanner',
	description: 'Manage Socket.dev API key',
	run: async () => {
		console.log('Socket.dev API Key Management');
		console.log('============================');
		console.log('');
		console.log('Available commands:');
		console.log('  set    - Set the API key');
		console.log('  delete - Delete the stored API key');
		console.log('  status - Show current configuration status');
		console.log('');
		console.log('Usage: bun run src/index.ts <command>');
	},
});

export async function runCli(): Promise<void> {
	const subCommands = new Map();
	subCommands.set('set', setCommand);
	subCommands.set('delete', deleteCommand);
	subCommands.set('status', statusCommand);

	await cli(process.argv.slice(2), mainCommand, {
		name: 'bun-socket-scanner',
		version: '0.1.0',
		description: 'Bun Socket.dev Security Scanner - API Key Management',
		subCommands,
	});
}
