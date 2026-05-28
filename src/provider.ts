/**
 * RepoProfileDetectorProvider — implements SecurityProvider for stage `repo.onboard`.
 *
 * Pure-JS profile detector. Walks `repoLocalPath` for marker files and
 * emits a single info finding describing the inferred profile and any
 * sibling profiles seen. No subprocess required.
 *
 * TODO: Wave 2 scaffold — real profile-classification model + policy
 * seeding is pending. This v1 only describes what was detected.
 */
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import type {
  NormalizedFinding,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

const PROFILE_VERSION = "1.0.0";

interface MarkerRule {
  marker: string;
  profile: string;
  reason: string;
}

// Highest-precedence-first ordering matters when multiple markers match.
const MARKERS: ReadonlyArray<MarkerRule> = [
  {
    marker: "capacitor.config.ts",
    profile: "mobile",
    reason: "Capacitor config detected",
  },
  {
    marker: "capacitor.config.js",
    profile: "mobile",
    reason: "Capacitor config detected",
  },
  {
    marker: "capacitor.config.json",
    profile: "mobile",
    reason: "Capacitor config detected",
  },
  {
    marker: "pubspec.yaml",
    profile: "mobile",
    reason: "Flutter pubspec detected",
  },
  {
    marker: "manifest.json",
    profile: "chrome-extension",
    reason: "Browser-extension manifest detected",
  },
  {
    marker: "Chart.yaml",
    profile: "iac",
    reason: "Helm chart detected",
  },
  {
    marker: "main.tf",
    profile: "iac",
    reason: "Terraform module detected",
  },
  {
    marker: "Cargo.toml",
    profile: "cli",
    reason: "Rust crate detected",
  },
  {
    marker: "go.mod",
    profile: "backend",
    reason: "Go module detected",
  },
  {
    marker: "package.json",
    profile: "backend",
    reason: "Node/Bun project detected (profile may be narrowed by sibling rules)",
  },
];

interface DetectionResult {
  detectedProfile: string;
  matchedMarkers: ReadonlyArray<{ marker: string; profile: string; reason: string }>;
  reason: string;
}

export class RepoProfileDetectorProvider implements SecurityProvider {
  readonly name = "repo-profile-detector";
  readonly stage: SecurityStage = "repo.onboard";
  readonly toolVersion = `repo-profile-detector@${PROFILE_VERSION}`;

  private host?: HostServices;

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // Pure-JS provider; no external binary to resolve.
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    input.onProgress?.({ pct: 10, message: "Walking repo for marker files" });

    let detection: DetectionResult;
    try {
      detection = await this.detect(input.repoLocalPath);
    } catch (err) {
      return {
        runId: input.runId,
        status: "errored",
        findings: [],
        evidence: [],
        durationMs: Date.now() - startedAt,
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        errorReason: `repo-profile-detector: ${String(err)}`,
      };
    }

    input.onProgress?.({ pct: 100, message: "Detection complete" });

    const fingerprint = createHash("sha256")
      .update(`${this.name}:${input.runId}:${detection.detectedProfile}`)
      .digest("hex");

    const finding: NormalizedFinding = {
      fingerprint,
      ruleId: `${this.name}.profile-detected`,
      title: `repo.onboard: detected profile = ${detection.detectedProfile}`,
      severity: "info",
      category: "config",
      description: detection.reason,
      rawProviderRef: JSON.stringify({
        detectedProfile: detection.detectedProfile,
        matchedMarkers: detection.matchedMarkers,
        stub: true,
        message:
          "Wave 2 scaffold: real profile-classification model + policy seeding pending; see src/provider.ts TODO.",
      }),
    };

    const summary: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 1 };

    return {
      runId: input.runId,
      status: "succeeded",
      findings: [finding],
      evidence: [],
      durationMs: Date.now() - startedAt,
      summary,
    };
  }

  async cancel(_runId: string): Promise<void> {
    // Detection is synchronous-ish and short-lived; nothing to cancel.
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: [
        "backend",
        "frontend",
        "cli",
        "sdk",
        "mcp",
        "chrome-extension",
        "vscode-extension",
        "mobile",
        "iac",
      ],
      toolVersion: this.toolVersion,
      description: "Repo profile detector for repo.onboard",
    };
  }

  private async detect(repoLocalPath: string): Promise<DetectionResult> {
    const matched: Array<{ marker: string; profile: string; reason: string }> = [];
    for (const rule of MARKERS) {
      const target = path.join(repoLocalPath, rule.marker);
      try {
        const stat = await fs.stat(target);
        if (stat.isFile()) {
          matched.push({ marker: rule.marker, profile: rule.profile, reason: rule.reason });
        }
      } catch {
        // marker not present
      }
    }

    if (matched.length === 0) {
      this.host?.logger?.warn?.(
        "repo-profile-detector",
        `no marker files detected under ${repoLocalPath}; defaulting to unknown profile`,
      );
      return {
        detectedProfile: "unknown",
        matchedMarkers: [],
        reason:
          "No recognized marker files (package.json, go.mod, Cargo.toml, Chart.yaml, manifest.json, pubspec.yaml, capacitor.config.*) were found in the repo root.",
      };
    }

    // Highest-precedence rule wins for the canonical detectedProfile.
    const winner = matched[0];
    if (!winner) {
      return {
        detectedProfile: "unknown",
        matchedMarkers: matched,
        reason: "Marker list was non-empty but the first entry was missing.",
      };
    }
    const reason =
      matched.length === 1
        ? winner.reason
        : `${winner.reason} (also matched: ${matched
            .slice(1)
            .map((m) => `${m.marker}→${m.profile}`)
            .join(", ")})`;

    return {
      detectedProfile: winner.profile,
      matchedMarkers: matched,
      reason,
    };
  }
}
