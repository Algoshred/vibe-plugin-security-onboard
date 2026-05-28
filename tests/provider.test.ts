import { describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";

import { RepoProfileDetectorProvider } from "../src/provider.js";
import type { SecurityScanInput } from "@vibecontrols/vibe-plugin-security/types";

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
    expect(meta.toolVersion).toBe("repo-profile-detector@1.0.0");
  });

  test("ensureToolInstalled() does not throw (pure JS provider)", async () => {
    const p = new RepoProfileDetectorProvider();
    await expect(p.ensureToolInstalled()).resolves.toBeUndefined();
  });

  test("run() against a temp repo returns succeeded with at least 1 info finding", async () => {
    const tempRepo = await mkdtemp(path.join(tmpdir(), "vc-onboard-test-"));
    try {
      await writeFile(path.join(tempRepo, "package.json"), '{"name":"x","version":"0.0.0"}');
      const p = new RepoProfileDetectorProvider();
      const input: SecurityScanInput = {
        runId: "run-1",
        vibeId: "v",
        workspaceId: "w",
        repoUrl: "https://example.com/x.git",
        repoLocalPath: tempRepo,
        commit: "deadbeef",
        stage: "repo.onboard",
        profile: { kind: "unknown", languages: [], runtimes: [] },
        policyLevel: "advisory",
        config: {},
        workdir: tempRepo,
      };
      const result = await p.run(input);
      expect(result.status).toBe("succeeded");
      expect(result.findings.length).toBeGreaterThanOrEqual(1);
      expect(result.summary.info).toBeGreaterThanOrEqual(1);
      const first = result.findings[0];
      expect(first).toBeDefined();
      if (first) {
        expect(first.severity).toBe("info");
        expect(first.category).toBe("config");
        expect(first.ruleId).toBe("repo-profile-detector.profile-detected");
      }
    } finally {
      await rm(tempRepo, { recursive: true, force: true });
    }
  });
});
