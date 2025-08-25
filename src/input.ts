import type { Buffer } from 'node:buffer';
import process from 'node:process';

/**
 * Reads password input from stdin with masking
 * @param prompt - The prompt message to display
 * @returns Promise that resolves to the entered password
 */
export async function readPassword(prompt: string = 'Enter API key: '): Promise<string> {
	return new Promise((resolve, reject) => {
		process.stdout.write(prompt);
		process.stdin.setRawMode(true);
		process.stdin.resume();

		let input = '';
		let cleanupCalled = false;

		const cleanup = (): void => {
			if (cleanupCalled) {
				return;
			}
			cleanupCalled = true;
			process.stdin.setRawMode(false);
			process.stdin.pause();
		};

		const onData = (chunk: Buffer): void => {
			const char = chunk.toString();

			if (char === '\r' || char === '\n') {
				// Enter key pressed
				cleanup();
				process.stdin.removeListener('data', onData);
				process.stdout.write('\n');
				resolve(input);
			}
			else if (char === '\x03') {
				// Ctrl+C pressed
				cleanup();
				process.stdin.removeListener('data', onData);
				process.stdout.write('\n');
				reject(new Error('User cancelled input'));
			}
			else if (char === '\x7F' || char === '\b') {
				// Backspace pressed
				if (input.length > 0) {
					input = input.slice(0, -1);
					process.stdout.write('\b \b');
				}
			}
			else if (char >= ' ') {
				// Printable character
				input += char;
				process.stdout.write('*');
			}
		};

		process.stdin.on('data', onData);
	});
}
