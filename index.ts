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
  version: "1",
  /**
   * Scans packages for security vulnerabilities and supply chain risks
   * @param packages - Array of packages to scan
   * @returns Promise resolving to array of security advisories
   */
  scan: async ({ packages }) => {
    const apiKey = getSocketApiKey();

    if (!apiKey) {
      console.warn('NI_SOCKETDEV_TOKEN not found, skipping security scan');
      return [];
    }

    const client = new SocketSdk(apiKey);
    const advisories: Bun.Security.Advisory[] = [];

    for (const pkg of packages) {
      try {
        const [issuesResult, scoreResult] = await Promise.allSettled([
          client.getIssuesByNPMPackage(pkg.name, pkg.version),
          client.getScoreByNPMPackage(pkg.name, pkg.version)
        ]);

        let hasIssues = false;
        let riskLevel: Bun.Security.Advisory['level'] | 'safe' = 'safe';
        let description = '';

        if (issuesResult.status === 'fulfilled' && issuesResult.value.success) {
          const issues = issuesResult.value.data;
          if (issues && issues.length > 0) {
            hasIssues = true;
            const criticalIssues = issues.filter((issue: any) => 
              issue.type?.includes('malware') || 
              issue.type?.includes('trojan') || 
              issue.type?.includes('backdoor')
            );

            if (criticalIssues.length > 0) {
              riskLevel = 'fatal';
              description = `Critical security issues found: ${criticalIssues.map((i: any) => i.type).join(', ')}`;
            } else {
              riskLevel = 'warn';
              description = `Security issues found: ${issues.map((i: any) => i.type).join(', ')}`;
            }
          }
        }

        if (scoreResult.status === 'fulfilled' && scoreResult.value.success) {
          const score = scoreResult.value.data;
          if (score?.supplyChainRisk?.score !== undefined) {
            const riskScore = score.supplyChainRisk.score;
            if (riskScore < FATAL_RISK_THRESHOLD) {
              if (riskLevel !== 'fatal') {
                riskLevel = 'fatal';
                description = `High supply chain risk (score: ${riskScore})`;
              }
            } else if (riskScore < WARN_RISK_THRESHOLD) {
              if (riskLevel !== 'fatal') {
                riskLevel = 'warn';
                if (!description) description = `Moderate supply chain risk (score: ${riskScore})`;
              }
            }
          }
        }

        if (riskLevel !== 'safe') {
          advisories.push({
            level: riskLevel,
            package: pkg.name,
            description: description || `Security concerns detected for ${pkg.name}@${pkg.version}`,
            url: `https://socket.dev/npm/package/${pkg.name}/overview/${pkg.version}`
          });
        }

      } catch (error) {
        console.warn(`Socket.dev API error for ${pkg.name}@${pkg.version}:`, error);
      }
    }

    return advisories;
  }
};

export default scanner;
