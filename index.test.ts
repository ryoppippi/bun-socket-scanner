import { test, expect, beforeEach, mock } from "bun:test";
import scanner from "./index";

// Mock the Socket SDK
const mockGetIssuesByNPMPackage = mock();
const mockGetScoreByNPMPackage = mock();

mock.module("@socketsecurity/sdk", () => ({
  SocketSdk: mock(() => ({
    getIssuesByNPMPackage: mockGetIssuesByNPMPackage,
    getScoreByNPMPackage: mockGetScoreByNPMPackage,
  })),
}));

beforeEach(() => {
  mockGetIssuesByNPMPackage.mockReset();
  mockGetScoreByNPMPackage.mockReset();
  process.env.NI_SOCKETDEV_TOKEN = "test-api-key";
});

test("scanner version should be 1", () => {
  expect(scanner.version).toBe("1");
});

test("should return empty array when no API key", async () => {
  delete process.env.NI_SOCKETDEV_TOKEN;
  const result = await scanner.scan({ packages: [] });
  expect(result).toEqual([]);
});

test("should return empty array for empty packages", async () => {
  mockGetIssuesByNPMPackage.mockResolvedValue({ success: true, data: [] });
  mockGetScoreByNPMPackage.mockResolvedValue({ success: true, data: { supplyChainRisk: { score: 0.8 } } });
  
  const result = await scanner.scan({ packages: [] });
  expect(result).toEqual([]);
});

test("should detect fatal risk for malware package", async () => {
  const malwarePackage = {
    name: "malicious-package",
    version: "1.0.0",
    tarball: "https://registry.npmjs.org/malicious-package/-/malicious-package-1.0.0.tgz",
    requestedRange: "^1.0.0"
  };

  mockGetIssuesByNPMPackage.mockResolvedValue({
    success: true,
    data: [{ 
      type: "malware_detected", 
      description: "Contains malicious code",
      value: { category: "supplyChainRisk", severity: "critical" }
    }]
  });
  mockGetScoreByNPMPackage.mockResolvedValue({
    success: true,
    data: { supplyChainRisk: { score: 0.1 } }
  });

  const result = await scanner.scan({ packages: [malwarePackage] });
  
  expect(result).toHaveLength(1);
  expect(result[0]).toEqual({
    level: "fatal",
    package: "malicious-package",
    description: "Supply chain risks found: critical malware_detected",
    url: "https://socket.dev/npm/package/malicious-package/overview/1.0.0"
  });
});

test("should detect warning for moderate risk package", async () => {
  const moderatePackage = {
    name: "moderate-package",
    version: "1.0.0",
    tarball: "https://registry.npmjs.org/moderate-package/-/moderate-package-1.0.0.tgz",
    requestedRange: "^1.0.0"
  };

  mockGetIssuesByNPMPackage.mockResolvedValue({
    success: true,
    data: [{ 
      type: "deprecated_api", 
      description: "Uses deprecated API",
      value: { category: "supplyChainRisk", severity: "middle" }
    }]
  });
  mockGetScoreByNPMPackage.mockResolvedValue({
    success: true,
    data: { supplyChainRisk: { score: 0.4 } }
  });

  const result = await scanner.scan({ packages: [moderatePackage] });
  
  expect(result).toHaveLength(1);
  expect(result[0]).toEqual({
    level: "warn",
    package: "moderate-package",
    description: "Supply chain risks found: middle deprecated_api",
    url: "https://socket.dev/npm/package/moderate-package/overview/1.0.0"
  });
});

test("should return empty for safe package", async () => {
  const safePackage = {
    name: "safe-package",
    version: "1.0.0",
    tarball: "https://registry.npmjs.org/safe-package/-/safe-package-1.0.0.tgz",
    requestedRange: "^1.0.0"
  };

  mockGetIssuesByNPMPackage.mockResolvedValue({
    success: true,
    data: []
  });
  mockGetScoreByNPMPackage.mockResolvedValue({
    success: true,
    data: { supplyChainRisk: { score: 0.9 } }
  });

  const result = await scanner.scan({ packages: [safePackage] });
  expect(result).toEqual([]);
});

test("should handle API errors gracefully", async () => {
  const testPackage = {
    name: "test-package",
    version: "1.0.0",
    tarball: "https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
    requestedRange: "^1.0.0"
  };

  mockGetIssuesByNPMPackage.mockRejectedValue(new Error("API Error"));
  mockGetScoreByNPMPackage.mockRejectedValue(new Error("API Error"));

  const result = await scanner.scan({ packages: [testPackage] });
  expect(result).toEqual([]);
});

test("should scan multiple packages", async () => {
  const packages = [
    {
      name: "safe-package",
      version: "1.0.0",
      tarball: "https://registry.npmjs.org/safe-package/-/safe-package-1.0.0.tgz",
      requestedRange: "^1.0.0"
    },
    {
      name: "risky-package",
      version: "2.0.0",
      tarball: "https://registry.npmjs.org/risky-package/-/risky-package-2.0.0.tgz",
      requestedRange: "^2.0.0"
    }
  ];

  mockGetIssuesByNPMPackage
    .mockResolvedValueOnce({ success: true, data: [] })
    .mockResolvedValueOnce({ success: true, data: [{ 
      type: "backdoor", 
      description: "Potential backdoor",
      value: { category: "supplyChainRisk", severity: "critical" }
    }] });
  
  mockGetScoreByNPMPackage
    .mockResolvedValueOnce({ success: true, data: { supplyChainRisk: { score: 0.9 } } })
    .mockResolvedValueOnce({ success: true, data: { supplyChainRisk: { score: 0.2 } } });

  const result = await scanner.scan({ packages });
  
  expect(result).toHaveLength(1);
  expect(result[0]?.package).toBe("risky-package");
  expect(result[0]?.level).toBe("fatal");
});

test("should prioritize fatal over warn based on score", async () => {
  const testPackage = {
    name: "test-package",
    version: "1.0.0",
    tarball: "https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
    requestedRange: "^1.0.0"
  };

  mockGetIssuesByNPMPackage.mockResolvedValue({
    success: true,
    data: [{ type: "deprecation", description: "Package deprecated" }] // Non-supplyChainRisk issue
  });
  mockGetScoreByNPMPackage.mockResolvedValue({
    success: true,
    data: { supplyChainRisk: { score: 0.1 } }
  });

  const result = await scanner.scan({ packages: [testPackage] });
  
  expect(result).toHaveLength(1);
  expect(result[0]?.level).toBe("fatal");
  expect(result[0]?.description).toContain("High supply chain risk");
});