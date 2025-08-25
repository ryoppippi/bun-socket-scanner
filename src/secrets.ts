import { secrets } from 'bun';
import {
	name as SERVICE_NAME,
} from '../package.json';

const API_KEY_NAME = 'socket-api-key';

/**
 * Retrieves the Socket.dev API key from environment variables or Bun.secrets
 * Priority: Environment variable (NI_SOCKETDEV_TOKEN) -> Bun.secrets
 * @returns The API key string if found, undefined otherwise
 */
export async function getApiKey(): Promise<string | undefined> {
	// First check environment variable
	const envKey = Bun.env.NI_SOCKETDEV_TOKEN;
	if (envKey != null && envKey !== '') {
		return envKey;
	}

	// Then check Bun.secrets
	try {
		const key = await secrets.get({
			service: SERVICE_NAME,
			name: API_KEY_NAME,
		});
		return key ?? undefined;
	}
	catch {
		return undefined;
	}
}

/**
 * Stores the Socket.dev API key securely using Bun.secrets
 * @param apiKey - The API key to store
 */
export async function setApiKey(apiKey: string): Promise<void> {
	await secrets.set({
		service: SERVICE_NAME,
		name: API_KEY_NAME,
		value: apiKey,
	});
}

/**
 * Deletes the stored Socket.dev API key from Bun.secrets
 */
export async function deleteApiKey(): Promise<void> {
	await secrets.delete({
		service: SERVICE_NAME,
		name: API_KEY_NAME,
	});
}

/**
 * Checks if an API key is configured (either via environment variable or Bun.secrets)
 * @returns true if an API key is available, false otherwise
 */
export async function hasApiKey(): Promise<boolean> {
	const key = await getApiKey();
	return key != null && key !== '';
}
