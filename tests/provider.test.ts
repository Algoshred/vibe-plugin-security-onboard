import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { RepoProfileDetectorProvider } from "../src/provider.js";
import type {
  NormalizedFinding,
  SecurityScanInput,
} from "@vibecontrols/vibe-plugin-security/types";

interface FixtureFile {
  rel: string;
  contents: string;
}

async function buildFixture(
  files: FixtureFile[],
): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(tmpdir(), "vc-onboard-test-"));
  for (const f of files) {
    const target = path.join(dir, f.rel);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, f.contents);
  }
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

function makeInput(repoLocalPath: string, config: Record<string, unknown> = {}): SecurityScanInput {
  return {
    runId: `run-${Math.random().toString(36).slice(2)}`,
    vibeId: "vibe-x",
    workspaceId: "ws-x",
    repoUrl: "https://example.com/x.git",
    repoLocalPath,
    commit: "deadbeef",
    stage: "repo.onboard",
    profile: { kind: "unknown", languages: [], runtimes: [] },
    policyLevel: "advisory",
    config,
    workdir: repoLocalPath,
  };
}

function profileFindings(findings: NormalizedFinding[]): NormalizedFinding[] {
  return findings.filter((f) => f.ruleId === "repo-profile-detector.profile-detected");
}

function detectedProfiles(findings: NormalizedFinding[]): string[] {
  return profileFindings(findings).map(
    (f) => (JSON.parse(f.rawProviderRef ?? "{}") as { profile: string }).profile,
  );
}

describe("RepoProfileDetectorProvider", () => {
  test("provider name + stage are stable identifiers", () => {
    const p = new RepoProfileDetectorProvider();
    expect(p.name).toBe("repo-profile-detector");
    expect(p.stage).toBe("repo.onboard");
  });

  test("metadata() reports stage + supported profiles", () => {
    const p = new RepoProfileDetectorProvider();
    const meta = p.metadata();
    expect(meta.stage).toBe("repo.onboard");
    expect(meta.supportedProfiles).toContain("backend");
    expect(meta.supportedProfiles).toContain("frontend");
    expect(meta.supportedProfiles).toContain("mobile");
    expect(meta.supportedProfiles).toContain("iac");
    expect(meta.supportedProfiles).toContain("mcp");
    expect(meta.supportedProfiles).toContain("gitops");
    expect(meta.toolVersion).toBe("repo-profile-detector@2.0.0");
  });

  test("ensureToolInstalled() does not throw (pure JS provider)", async () => {
    const p = new RepoProfileDetectorProvider();
    await expect(p.ensureToolInstalled()).resolves.toBeUndefined();
  });

  test("package.json + vite.config → frontend profile", async () => {
    const { dir, cleanup } = await buildFixture([
      {
        rel: "package.json",
        contents: JSON.stringify({
          name: "fe",
          version: "1.0.0",
          dependencies: { react: "19", vite: "7" },
        }),
      },
      { rel: "vite.config.ts", contents: "export default {}" },
    ]);
    try {
      const p = new RepoProfileDetectorProvider();
      const result = await p.run(makeInput(dir));
      expect(result.status).toBe("succeeded");
      expect(detectedProfiles(result.findings)).toContain("frontend");
      // Recommendation must include the frontend-specific DAST preview stage.
      const fe = profileFindings(result.findings).find(
        (f) => (JSON.parse(f.rawProviderRef ?? "{}") as { profile: string }).profile === "frontend",
      );
      expect(fe).toBeDefined();
      const ref = JSON.parse(fe!.rawProviderRef ?? "{}") as { recommendedStages: string[] };
      expect(ref.recommendedStages).toContain("deploy.preview");
    } finally {
      await cleanup();
    }
  });

  test("Dockerfile + prisma → backend (+ container) profile", async () => {
    const { dir, cleanup } = await buildFixture([
      {
        rel: "package.json",
        contents: JSON.stringify({ name: "be", version: "1.0.0", dependencies: { elysia: "1" } }),
      },
      { rel: "Dockerfile", contents: "FROM oven/bun" },
      { rel: "prisma/schema.prisma", contents: "datasource db {}" },
    ]);
    try {
      const p = new RepoProfileDetectorProvider();
      const result = await p.run(makeInput(dir));
      expect(result.status).toBe("succeeded");
      const profiles = detectedProfiles(result.findings);
      expect(profiles).toContain("backend");
      expect(profiles).toContain("container");
    } finally {
      await cleanup();
    }
  });

  test("terraform/*.tf → iac profile", async () => {
    const { dir, cleanup } = await buildFixture([
      { rel: "main.tf", contents: 'resource "null_resource" "x" {}' },
      { rel: "terraform/vpc.tf", contents: "# vpc" },
    ]);
    try {
      const p = new RepoProfileDetectorProvider();
      const result = await p.run(makeInput(dir));
      expect(result.status).toBe("succeeded");
      expect(detectedProfiles(result.findings)).toContain("iac");
    } finally {
      await cleanup();
    }
  });

  test("mcp.json / @modelcontextprotocol dep → mcp profile", async () => {
    const { dir, cleanup } = await buildFixture([
      {
        rel: "package.json",
        contents: JSON.stringify({
          name: "mcp-srv",
          version: "1.0.0",
          dependencies: { "@modelcontextprotocol/sdk": "1.0.0" },
        }),
      },
    ]);
    try {
      const p = new RepoProfileDetectorProvider();
      const result = await p.run(makeInput(dir));
      expect(detectedProfiles(result.findings)).toContain("mcp");
    } finally {
      await cleanup();
    }
  });

  test("src/extension.ts + contributes → vscode_extension profile", async () => {
    const { dir, cleanup } = await buildFixture([
      {
        rel: "package.json",
        contents: JSON.stringify({ name: "ext", version: "1.0.0", contributes: { commands: [] } }),
      },
      { rel: "src/extension.ts", contents: "export function activate() {}" },
    ]);
    try {
      const p = new RepoProfileDetectorProvider();
      const result = await p.run(makeInput(dir));
      expect(detectedProfiles(result.findings)).toContain("vscode_extension");
    } finally {
      await cleanup();
    }
  });

  test("emits an info finding per profile + a medium ownership-missing finding", async () => {
    const { dir, cleanup } = await buildFixture([
      {
        rel: "package.json",
        contents: JSON.stringify({ name: "x", version: "0.0.0", dependencies: { react: "19" } }),
      },
      { rel: "vite.config.ts", contents: "export default {}" },
    ]);
    try {
      const p = new RepoProfileDetectorProvider();
      const result = await p.run(makeInput(dir)); // no owner/criticality in config
      expect(result.status).toBe("succeeded");
      expect(result.summary.info).toBeGreaterThanOrEqual(1);
      const ownership = result.findings.find(
        (f) => f.ruleId === "repo-profile-detector.ownership-missing",
      );
      expect(ownership).toBeDefined();
      expect(ownership!.severity).toBe("medium");
      expect(result.summary.medium).toBe(1);
    } finally {
      await cleanup();
    }
  });

  test("criticality metadata drives policy level + suppresses ownership finding", async () => {
    const { dir, cleanup } = await buildFixture([
      {
        rel: "package.json",
        contents: JSON.stringify({ name: "be", version: "1", dependencies: { elysia: "1" } }),
      },
      { rel: "Dockerfile", contents: "FROM oven/bun" },
    ]);
    try {
      const p = new RepoProfileDetectorProvider();
      const result = await p.run(makeInput(dir, { owner: "platform-team", tier: 0 }));
      // tier_0 → block policy.
      const profile = profileFindings(result.findings)[0];
      expect(profile).toBeDefined();
      const ref = JSON.parse(profile!.rawProviderRef ?? "{}") as { policyLevel: string };
      expect(ref.policyLevel).toBe("block");
      // owner + tier present → no ownership-missing finding.
      const ownership = result.findings.find(
        (f) => f.ruleId === "repo-profile-detector.ownership-missing",
      );
      expect(ownership).toBeUndefined();
    } finally {
      await cleanup();
    }
  });

  test("emits a JSON evidence artifact (no {stub:true} marker anywhere)", async () => {
    const { dir, cleanup } = await buildFixture([
      { rel: "package.json", contents: JSON.stringify({ name: "x", version: "0.0.0" }) },
    ]);
    try {
      const p = new RepoProfileDetectorProvider();
      const result = await p.run(makeInput(dir, { owner: "team", criticality: "standard" }));
      expect(result.status).toBe("succeeded");
      expect(result.evidence.length).toBeGreaterThanOrEqual(1);
      const ev = result.evidence[0];
      expect(ev).toBeDefined();
      expect(ev!.sha256).toHaveLength(64);
      expect(ev!.sizeBytes).toBeGreaterThan(0);
      // No finding may carry a stub marker.
      for (const f of result.findings) {
        const ref = JSON.parse(f.rawProviderRef ?? "{}") as Record<string, unknown>;
        expect(ref.stub).toBeUndefined();
      }
    } finally {
      await cleanup();
    }
  });

  test("persists config best-effort via host.workspaceQuery when available", async () => {
    const { dir, cleanup } = await buildFixture([
      {
        rel: "package.json",
        contents: JSON.stringify({ name: "be", version: "1", dependencies: { express: "4" } }),
      },
    ]);
    try {
      let capturedVars: Record<string, unknown> | undefined;
      const host = {
        workspaceQuery: async <T>(_q: string, vars?: Record<string, unknown>) => {
          capturedVars = vars;
          return {
            data: { updateRepositorySecurityConfig: { id: "cfg-1", policyLevel: "WARN" } },
          } as { data: T };
        },
      };
      const p = new RepoProfileDetectorProvider();
      // The contract types are intentionally loosened; cast the minimal host.
      await p.init(host as unknown as Parameters<RepoProfileDetectorProvider["init"]>[0]);
      const result = await p.run(makeInput(dir, { owner: "team", criticality: "standard" }));
      expect(result.status).toBe("succeeded");
      expect(capturedVars).toBeDefined();
      const input = (capturedVars as { input: { enabledStages: string[]; policyLevel: string } })
        .input;
      expect(input.policyLevel).toBe("WARN");
      // Stages are sent as backend SCREAMING_SNAKE enum values.
      expect(input.enabledStages).toContain("PULL_REQUEST_FAST");
      // The profile finding reports the persisted state.
      const profile = profileFindings(result.findings)[0];
      const ref = JSON.parse(profile!.rawProviderRef ?? "{}") as { configPersisted: boolean };
      expect(ref.configPersisted).toBe(true);
    } finally {
      await cleanup();
    }
  });

  test("run() against an empty repo returns succeeded + profile-unknown info finding", async () => {
    const { dir, cleanup } = await buildFixture([]);
    try {
      const p = new RepoProfileDetectorProvider();
      const result = await p.run(makeInput(dir, { owner: "team", criticality: "standard" }));
      expect(result.status).toBe("succeeded");
      const unknown = result.findings.find(
        (f) => f.ruleId === "repo-profile-detector.profile-unknown",
      );
      expect(unknown).toBeDefined();
      expect(unknown!.severity).toBe("info");
      expect(unknown!.category).toBe("config");
    } finally {
      await cleanup();
    }
  });
});
