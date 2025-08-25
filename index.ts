import { SocketSdk } from '@socketsecurity/sdk';

/** Threshold for fatal security risk level (below this score triggers fatal advisory) */
const FATAL_RISK_THRESHOLD = 0.3;

/** Threshold for warning security risk level (below this score triggers warning advisory) */
const WARN_RISK_THRESHOLD = 0.5;

/**
 * Retrieves the Socket.dev API key from environment variables
 * @returns The API key string if found, undefined otherwise
 */
function getSocketApiKey(): string | undefined {
	return Bun.env.NI_SOCKETDEV_TOKEN;
}

/**
 * Bun security scanner that integrates with Socket.dev to detect package vulnerabilities
 * and supply chain risks during package installation.
 */
const scanner: Bun.Security.Scanner = {
	version: '1',
	/**
	 * Scans packages for security vulnerabilities and supply chain risks
	 * @param packages - The package configuration containing an array of packages to scan
	 * @param packages.packages - Array of packages to scan
	 * @returns Promise resolving to array of security advisories
	 */
	scan: async ({ packages }) => {
		const apiKey = getSocketApiKey();

		if (apiKey === undefined || apiKey === '') {
			console.warn('NI_SOCKETDEV_TOKEN not found, skipping security scan');
			return [];
		}

		const client = new SocketSdk(apiKey);
		const advisories: Bun.Security.Advisory[] = [];

		for (const pkg of packages) {
			try {
				const [issuesResult, scoreResult] = await Promise.allSettled([
					client.getIssuesByNPMPackage(pkg.name, pkg.version),
					client.getScoreByNPMPackage(pkg.name, pkg.version),
				]);

				let riskLevel: Bun.Security.Advisory['level'] | 'safe' = 'safe';
				let description = '';

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
							const firstIssue = sortedIssues[0] as { value?: { severity?: string } } | undefined;
							const highestSeverity = firstIssue?.value?.severity;

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
								if (description === '') {
									description = `Moderate supply chain risk (score: ${riskScore})`;
								}
							}
						}
					}
				}

				if (riskLevel !== 'safe') {
					// Use issue-specific URL format like ni.zsh when we have specific issue types
					let url = `https://socket.dev/npm/package/${pkg.name}/overview/${pkg.version}`;
					if (description.includes('Supply chain risks found:')) {
						// For now, keep the package overview URL as we may have multiple issue types
						url = `https://socket.dev/npm/package/${pkg.name}/overview/${pkg.version}`;
					}

					advisories.push({
						level: riskLevel,
						package: pkg.name,
						description: description !== '' ? description : `Security concerns detected for ${pkg.name}@${pkg.version}`,
						url,
					});
				}
			}
			catch (error) {
				console.warn(`Socket.dev API error for ${pkg.name}@${pkg.version}:`, error);
			}
		}

		return advisories;
	},
};

export default scanner;
