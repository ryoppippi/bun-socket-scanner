import { runCli } from './cli';
import { scanner } from './scanner';

// Export the scanner for use as Bun security scanner
export { scanner };

// CLI entry point
if (import.meta.main) {
	// eslint-disable-next-line antfu/no-top-level-await
	await runCli();
}
