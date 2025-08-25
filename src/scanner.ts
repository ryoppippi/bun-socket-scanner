import { SocketSdk } from '@socketsecurity/sdk';
import { logger } from './logger';
import { getApiKey } from './secrets';

/** Threshold for fatal security risk level (below this score triggers fatal advisory) */
const FATAL_RISK_THRESHOLD = 0.3;

/** Threshold for warning security risk level (below this score triggers warning advisory) */
const WARN_RISK_THRESHOLD = 0.5;

/**
 * Bun security scanner that integrates with Socket.dev to detect package vulnerabilities
 * and supply chain risks during package installation.
 */
export const scanner: Bun.Security.Scanner = {
	version: '1',
	/**
	 * Scans packages for security vulnerabilities and supply chain risks
	 * @param packages - The package configuration containing an array of packages to scan
	 * @param packages.packages - Array of packages to scan
	 * @returns Promise resolving to array of security advisories
	 */
	scan: async ({ packages }) => {
		const apiKey = await getApiKey();

		if (apiKey == null || apiKey === '') {
			throw new Error('Socket.dev API key not found. Configure with: bun run src/index.ts set or set NI_SOCKETDEV_TOKEN environment variable');
		}

		const client = new SocketSdk(apiKey);
		const advisories: Bun.Security.Advisory[] = [];

		const scanResults = await Promise.allSettled(
			packages.map(async (pkg) => {
				logger.info(`Scanning package: ${pkg.name}@${pkg.version}`);
				try {
					const [issuesResult, scoreResult] = await Promise.allSettled([
						client.getIssuesByNPMPackage(pkg.name, pkg.version),
						client.getScoreByNPMPackage(pkg.name, pkg.version),
					]);

					let riskLevel: Bun.Security.Advisory['level'] | 'safe' = 'safe';
					let description = '';
					let primaryIssueType: string | undefined;

					if (issuesResult.status === 'fulfilled' && issuesResult.value.success) {
						const issues = issuesResult.value.data;
						if (issues.length > 0) {
							// Filter for supplyChainRisk category issues like ni.zsh
							const supplyChainIssues = issues.filter((issue: unknown) => {
								const issueValue = issue as { value?: { category?: string } };
								return issueValue.value?.category === 'supplyChainRisk';
							});

							if (supplyChainIssues.length > 0) {
								// Sort by severity: critical > high > middle > low
								const severityOrder = ['critical', 'high', 'middle', 'low'];
								const sortedIssues = supplyChainIssues.sort((a: unknown, b: unknown) => {
									const aValue = a as { value?: { severity?: string } };
									const bValue = b as { value?: { severity?: string } };
									const aIndex = severityOrder.indexOf(aValue.value?.severity ?? '');
									const bIndex = severityOrder.indexOf(bValue.value?.severity ?? '');
									return aIndex - bIndex;
								});

								// Get highest severity issue
								const firstIssue = sortedIssues[0] as { value?: { severity?: string }; type?: string } | undefined;
								const highestSeverity = firstIssue?.value?.severity;
								primaryIssueType = firstIssue?.type;

								if (highestSeverity === 'critical' || highestSeverity === 'high') {
									riskLevel = 'fatal';
								}
								else {
									riskLevel = 'warn';
								}

								// Create message like ni.zsh format
								const messages = sortedIssues.map((issue: unknown) => {
									const issueTyped = issue as { value?: { severity?: string }; type?: string };
									return `${issueTyped.value?.severity ?? ''} ${issueTyped.type ?? ''}`;
								}).filter((msg: string, index: number, array: string[]) =>
									array.indexOf(msg) === array.lastIndexOf(msg), // Remove duplicates
								);

								description = `Supply chain risks found: ${messages.join(', ')}`;
							}
							else {
								riskLevel = 'warn';
								const issueTypes = issues.map((i: unknown) => {
									const issue = i as { type?: string };
									return issue.type ?? 'unknown';
								});
								description = `Security issues found: ${issueTypes.join(', ')}`;
							}
						}
					}

					if (scoreResult.status === 'fulfilled' && scoreResult.value.success) {
						const score = scoreResult.value.data;
						if (score?.supplyChainRisk?.score != null) {
							const riskScore = score.supplyChainRisk.score;
							if (riskScore < FATAL_RISK_THRESHOLD) {
								if (riskLevel !== 'fatal') {
									riskLevel = 'fatal';
									description = `High supply chain risk (score: ${riskScore})`;
								}
							}
							else if (riskScore < WARN_RISK_THRESHOLD) {
								if (riskLevel !== 'fatal') {
									riskLevel = 'warn';
									if (description == null || description === '') {
										description = `Moderate supply chain risk (score: ${riskScore})`;
									}
								}
							}
						}
					}

					if (riskLevel !== 'safe') {
						// Use issue-specific URL format like ni.zsh when we have specific issue types
						let url = `https://socket.dev/npm/package/${pkg.name}/overview/${pkg.version}`;

						// For supply chain risks, use issue-specific URL like ni.zsh
						if (description.includes('Supply chain risks found:') && primaryIssueType != null && primaryIssueType !== '') {
							url = `https://socket.dev/npm/issue/${primaryIssueType}`;
						}

						return {
							level: riskLevel,
							package: pkg.name,
							description: description != null && description !== '' ? description : `Security concerns detected for ${pkg.name}@${pkg.version}`,
							url,
						} satisfies Bun.Security.Advisory;
					}

					return null;
				}
				catch (error) {
					logger.warn(`Socket.dev API error for ${pkg.name}@${pkg.version}:`, error);
					return null;
				}
			}),
		);

		// Collect successful results
		for (const result of scanResults) {
			if (result.status === 'fulfilled' && result.value != null) {
				advisories.push(result.value);
			}
		}

		return advisories;
	},
};
