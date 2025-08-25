/**
 * @fileoverview Logging utilities for the ccusage application
 *
 * This module provides configured logger instances using consola for consistent
 * logging throughout the application with package name tagging.
 *
 * @module logger
 */

import type { ConsolaInstance } from 'consola';
import { consola } from 'consola';

import { name } from '../package.json';

/**
 * Application logger instance with package name tag
 */
export const logger: ConsolaInstance = consola.withTag(name);

// Apply LOG_LEVEL environment variable if set
if (Bun.env.LOG_LEVEL != null) {
	const level = Number.parseInt(Bun.env.LOG_LEVEL, 10);
	if (!Number.isNaN(level)) {
		logger.level = level;
	}
}
