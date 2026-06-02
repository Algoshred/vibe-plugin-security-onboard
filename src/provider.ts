/**
 * RepoProfileDetectorProvider — implements SecurityProvider for stage `repo.onboard`.
 *
 * Pure-JS onboarding provider. It does three real things, none of which
 * require a subprocess:
 *
 *   1. Classifies the repo into one or more profiles (frontend / backend /
 *      cli / sdk / mcp / chrome_extension / vscode_extension / mobile / iac /
 *      container / gitops) using the marker-file + package.json rules from
 *      the security spec §4.1.
 *   2. Seeds a default `RepositorySecurityConfig` — the recommended enabled
 *      lifecycle stages per detected profile (spec §4.2 "default controls by
 *      repo type") plus a default policy level derived from repo criticality.
 *      When the host exposes `workspaceQuery` it persists this via the
 *      backend `updateRepositorySecurityConfig` mutation (best-effort); either
 *      way it surfaces the recommendation as an `info` finding + an evidence
 *      artifact so the orchestrator / UI can apply it.
 *   3. Emits findings: one `info` per detected profile describing its
 *      recommended stages, and a blocking-eligible `medium` finding when
 *      ownership / criticality metadata is missing.
 *
 * Onboarding never fails — its output is purely informational and drives the
 * smart defaults in the Security tab (see stage-01-repo-onboard.md).
 */
import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import * as path from "node:path";

import type { HostServices } from "@vibecontrols/plugin-sdk/contract";
import type {
  NormalizedFinding,
  ScanEvidenceArtifact,
  SecurityPolicyLevel,
  SecurityProvider,
  SecurityProviderMetadata,
  SecurityScanInput,
  SecurityScanResult,
  SecurityScanSummary,
  SecurityStage,
} from "@vibecontrols/vibe-plugin-security/types";

const PROFILE_VERSION = "2.0.0";

// ── Profile taxonomy ────────────────────────────────────────────────────

export type RepoProfile =
  | "frontend"
  | "backend"
  | "cli"
  | "sdk"
  | "mcp"
  | "chrome_extension"
  | "vscode_extension"
  | "mobile"
  | "iac"
  | "container"
  | "gitops";

const ALL_PROFILES: readonly RepoProfile[] = [
  "frontend",
  "backend",
  "cli",
  "sdk",
  "mcp",
  "chrome_extension",
  "vscode_extension",
  "mobile",
  "iac",
  "container",
  "gitops",
];

// ── Default controls by repo type (spec §4.2) ──────────────────────────
//
// Maps each profile to the recommended lifecycle stages it should opt into.
// `repo.onboard` itself is implicitly always-on, so it is not repeated here.
// `developer.local`, `pull_request.fast`, `pull_request.deep`, `main.merge`,
// `scheduled.rescan`, `archive.offboard` form a baseline that applies to every
// profile; per-profile extras layer build / publish / deploy / runtime stages.

const BASELINE_STAGES: readonly SecurityStage[] = [
  "developer.local",
  "pull_request.fast",
  "pull_request.deep",
  "main.merge",
  "scheduled.rescan",
  "archive.offboard",
];

const PROFILE_STAGE_EXTRAS: Record<RepoProfile, readonly SecurityStage[]> = {
  // SAST, dep scan, secret scan, source-map leak, CSP, DAST on preview URL.
  frontend: ["build", "deploy.preview", "deploy.alpha", "promote.prod", "runtime.continuous"],
  // SAST, SCA, secrets, Dockerfile scan, image scan, SBOM, signing, IaC.
  backend: [
    "build",
    "package.publish",
    "deploy.preview",
    "deploy.alpha",
    "promote.prod",
    "runtime.continuous",
  ],
  // SAST, dep scan, shell-injection, binary/package signing.
  cli: ["build", "package.publish", "promote.prod"],
  // Dep/license scan, package provenance, public-API leak, publishing guard.
  sdk: ["build", "package.publish", "promote.prod"],
  // Tool input validation, OAuth/OIDC, per-tool authz, prompt-injection.
  mcp: ["build", "package.publish", "deploy.preview", "promote.prod", "runtime.continuous"],
  // Manifest permission audit, content-script risk, CSP, OAuth flow.
  chrome_extension: ["build", "package.publish", "promote.prod"],
  // Webview CSP, command injection, workspace trust, secret storage.
  vscode_extension: ["build", "package.publish", "promote.prod"],
  // Static/dynamic scan, signing config, keystore, network security config.
  mobile: ["build", "package.publish", "promote.prod"],
  // Terraform/K8s/Helm misconfig, policy-as-code, digest pinning, RBAC.
  iac: ["build", "deploy.preview", "deploy.alpha", "promote.prod", "runtime.continuous"],
  // OS/package CVE scan, malware, non-root, base-image age, SBOM, signature.
  container: ["build", "package.publish", "promote.prod", "runtime.continuous"],
  // Manifest validation, policy checks, digest verification, promotion evidence.
  gitops: ["deploy.preview", "deploy.alpha", "promote.prod", "runtime.continuous"],
};

// GQL enum value mappings — must match the server-side SecurityStage /
// SecurityPolicyLevel enums consumed by `updateRepositorySecurityConfig`.
const GQL_STAGES: Record<SecurityStage, string> = {
  "repo.onboard": "REPO_ONBOARD",
  "developer.local": "DEVELOPER_LOCAL",
  "pull_request.fast": "PULL_REQUEST_FAST",
  "pull_request.deep": "PULL_REQUEST_DEEP",
  "main.merge": "MAIN_MERGE",
  build: "BUILD",
  "package.publish": "PACKAGE_PUBLISH",
  "deploy.preview": "DEPLOY_PREVIEW",
  "deploy.alpha": "DEPLOY_ALPHA",
  "promote.prod": "PROMOTE_PROD",
  "runtime.continuous": "RUNTIME_CONTINUOUS",
  "scheduled.rescan": "SCHEDULED_RESCAN",
  "incident.response": "INCIDENT_RESPONSE",
  "archive.offboard": "ARCHIVE_OFFBOARD",
};

const GQL_POLICY_LEVELS: Record<SecurityPolicyLevel, string> = {
  advisory: "ADVISORY",
  warn: "WARN",
  block: "BLOCK",
};

const UPDATE_CONFIG_MUTATION = `
  mutation UpdateRepositorySecurityConfig(
    $vibeId: ID!
    $input: UpdateRepositorySecurityConfigInput!
  ) {
    updateRepositorySecurityConfig(vibeId: $vibeId, input: $input) {
      id
      policyLevel
    }
  }
`;

// ── Detection model ─────────────────────────────────────────────────────

interface FileProbe {
  /** Repo-relative path to test (file or directory). */
  rel: string;
  /** "file" requires a regular file; "dir" requires a directory; "any" either. */
  kind: "file" | "dir" | "any";
  /** Match by basename glob `*.tf` etc. when scanning a directory listing. */
  glob?: string;
  profile: RepoProfile;
  reason: string;
}

// Marker probes derived from spec §4.1. Glob probes are evaluated against the
// repo-root listing; plain `rel` probes stat a specific path.
const PROBES: readonly FileProbe[] = [
  // frontend
  { rel: "vite.config.ts", kind: "file", profile: "frontend", reason: "Vite config" },
  { rel: "vite.config.js", kind: "file", profile: "frontend", reason: "Vite config" },
  { rel: "vite.config.mjs", kind: "file", profile: "frontend", reason: "Vite config" },
  { rel: "next.config.js", kind: "file", profile: "frontend", reason: "Next.js config" },
  { rel: "next.config.mjs", kind: "file", profile: "frontend", reason: "Next.js config" },
  { rel: "next.config.ts", kind: "file", profile: "frontend", reason: "Next.js config" },
  {
    rel: "src/main.tsx",
    kind: "file",
    profile: "frontend",
    reason: "React entrypoint src/main.tsx",
  },
  { rel: "src/App.tsx", kind: "file", profile: "frontend", reason: "React component src/App.tsx" },
  // backend
  { rel: "Dockerfile", kind: "file", profile: "container", reason: "Dockerfile (container image)" },
  { rel: "prisma/schema.prisma", kind: "file", profile: "backend", reason: "Prisma schema" },
  { rel: "graphql/schema.graphql", kind: "file", profile: "backend", reason: "GraphQL schema" },
  { rel: "openapi.yaml", kind: "file", profile: "backend", reason: "OpenAPI spec" },
  { rel: "openapi.yml", kind: "file", profile: "backend", reason: "OpenAPI spec" },
  {
    rel: "src/server.ts",
    kind: "file",
    profile: "backend",
    reason: "Server entrypoint src/server.ts",
  },
  {
    rel: "src/server.js",
    kind: "file",
    profile: "backend",
    reason: "Server entrypoint src/server.js",
  },
  { rel: "go.mod", kind: "file", profile: "backend", reason: "Go module" },
  {
    rel: "pyproject.toml",
    kind: "file",
    profile: "backend",
    reason: "Python project (pyproject.toml)",
  },
  // cli
  { rel: "bin", kind: "dir", profile: "cli", reason: "bin/ directory" },
  { rel: "Cargo.toml", kind: "file", profile: "cli", reason: "Rust crate (Cargo.toml)" },
  // mcp
  { rel: "mcp.json", kind: "file", profile: "mcp", reason: "MCP manifest mcp.json" },
  // chrome_extension
  {
    rel: "manifest.json",
    kind: "file",
    profile: "chrome_extension",
    reason: "Browser-extension manifest.json",
  },
  {
    rel: "src/background.ts",
    kind: "file",
    profile: "chrome_extension",
    reason: "Extension background script",
  },
  {
    rel: "src/background.js",
    kind: "file",
    profile: "chrome_extension",
    reason: "Extension background script",
  },
  {
    rel: "src/content.ts",
    kind: "file",
    profile: "chrome_extension",
    reason: "Extension content script",
  },
  {
    rel: "src/content.js",
    kind: "file",
    profile: "chrome_extension",
    reason: "Extension content script",
  },
  // vscode_extension
  {
    rel: "src/extension.ts",
    kind: "file",
    profile: "vscode_extension",
    reason: "VS Code extension entrypoint",
  },
  {
    rel: "src/extension.js",
    kind: "file",
    profile: "vscode_extension",
    reason: "VS Code extension entrypoint",
  },
  // mobile
  { rel: "android", kind: "dir", profile: "mobile", reason: "android/ directory" },
  { rel: "ios", kind: "dir", profile: "mobile", reason: "ios/ directory" },
  { rel: "fastlane", kind: "dir", profile: "mobile", reason: "fastlane/ directory" },
  { rel: "capacitor.config.ts", kind: "file", profile: "mobile", reason: "Capacitor config" },
  { rel: "capacitor.config.js", kind: "file", profile: "mobile", reason: "Capacitor config" },
  { rel: "capacitor.config.json", kind: "file", profile: "mobile", reason: "Capacitor config" },
  { rel: "pubspec.yaml", kind: "file", profile: "mobile", reason: "Flutter pubspec" },
  { rel: "react-native.config.js", kind: "file", profile: "mobile", reason: "React Native config" },
  // iac
  { rel: "terraform", kind: "dir", profile: "iac", reason: "terraform/ directory" },
  { rel: "k8s", kind: "dir", profile: "iac", reason: "k8s/ directory" },
  { rel: "helm", kind: "dir", profile: "iac", reason: "helm/ directory" },
  { rel: "Chart.yaml", kind: "file", profile: "iac", reason: "Helm chart (Chart.yaml)" },
  { rel: "kustomization.yaml", kind: "file", profile: "iac", reason: "Kustomize overlay" },
  { rel: "kustomization.yml", kind: "file", profile: "iac", reason: "Kustomize overlay" },
  // glob: any *.tf at repo root → iac
  { rel: ".", kind: "any", glob: "*.tf", profile: "iac", reason: "Terraform files (*.tf)" },
];

interface ProfileMatch {
  profile: RepoProfile;
  reasons: string[];
}

interface OwnershipMeta {
  owner?: string;
  criticality?: string;
  tier?: number;
}

interface DetectionResult {
  profiles: ProfileMatch[];
  /** The canonical, highest-precedence single profile (UI summary). */
  primary: RepoProfile | "unknown";
  ownership: OwnershipMeta;
}

// Precedence when collapsing the profile set into a single canonical profile.
// More specific repo shapes win over the generic node/container fallbacks.
const PRIMARY_PRECEDENCE: readonly RepoProfile[] = [
  "mcp",
  "chrome_extension",
  "vscode_extension",
  "mobile",
  "iac",
  "gitops",
  "cli",
  "frontend",
  "sdk",
  "backend",
  "container",
];

interface ParsedPackageJson {
  isFrontend: boolean;
  isCli: boolean;
  isMcp: boolean;
  isVscodeExtension: boolean;
  isSdk: boolean;
  isBackend: boolean;
}

export class RepoProfileDetectorProvider implements SecurityProvider {
  readonly name = "repo-profile-detector";
  readonly stage: SecurityStage = "repo.onboard";
  readonly toolVersion = `repo-profile-detector@${PROFILE_VERSION}`;

  private host?: HostServices;
  private cancelled = new Set<string>();

  async init(host: HostServices): Promise<void> {
    this.host = host;
  }

  async ensureToolInstalled(): Promise<void> {
    // Onboarding is pure profile classification — no external binary needed.
  }

  async run(input: SecurityScanInput): Promise<SecurityScanResult> {
    const startedAt = Date.now();
    input.onProgress?.({ pct: 10, message: "Walking repo for marker files" });

    let detection: DetectionResult;
    try {
      detection = await this.detect(input);
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

    if (this.cancelled.has(input.runId)) {
      this.cancelled.delete(input.runId);
      return {
        runId: input.runId,
        status: "cancelled",
        findings: [],
        evidence: [],
        durationMs: Date.now() - startedAt,
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      };
    }

    input.onProgress?.({ pct: 50, message: "Classifying profile + seeding defaults" });

    const recommendation = this.buildRecommendation(detection, input);

    // Best-effort persistence of the seeded config. Onboarding must never
    // fail because the backend was unreachable, so persistence errors are
    // downgraded to a logged warning + reflected in the evidence ref.
    const persistence = await this.persistConfig(input, recommendation);

    const findings = this.buildFindings(input, detection, recommendation, persistence);

    let evidence: ScanEvidenceArtifact[] = [];
    try {
      evidence = [await this.writeEvidence(input, detection, recommendation, persistence)];
    } catch (err) {
      this.host?.logger?.warn?.(
        "repo-profile-detector",
        `failed to write onboarding evidence: ${String(err)}`,
      );
    }

    input.onProgress?.({ pct: 100, message: "Onboarding complete" });

    const summary = this.summarize(findings);

    return {
      runId: input.runId,
      status: "succeeded",
      findings,
      evidence,
      durationMs: Date.now() - startedAt,
      summary,
    };
  }

  async cancel(runId: string): Promise<void> {
    this.cancelled.add(runId);
  }

  metadata(): SecurityProviderMetadata {
    return {
      stage: this.stage,
      supportedProfiles: [...ALL_PROFILES],
      toolVersion: this.toolVersion,
      description: "Repo profile detector + default-policy seeder for repo.onboard",
    };
  }

  // ── Detection ───────────────────────────────────────────────────────

  private async detect(input: SecurityScanInput): Promise<DetectionResult> {
    const repoLocalPath = input.repoLocalPath;
    const byProfile = new Map<RepoProfile, ProfileMatch>();

    const addMatch = (profile: RepoProfile, reason: string): void => {
      const existing = byProfile.get(profile);
      if (existing) {
        if (!existing.reasons.includes(reason)) existing.reasons.push(reason);
      } else {
        byProfile.set(profile, { profile, reasons: [reason] });
      }
    };

    // Snapshot the repo-root listing once for glob probes.
    const rootEntries = await readdirSafe(repoLocalPath);

    for (const probe of PROBES) {
      if (probe.glob) {
        const re = globToRegExp(probe.glob);
        if (rootEntries.some((e) => re.test(e))) addMatch(probe.profile, probe.reason);
        continue;
      }
      const target = path.join(repoLocalPath, probe.rel);
      try {
        const stat = await fs.stat(target);
        const ok =
          probe.kind === "any" ||
          (probe.kind === "file" && stat.isFile()) ||
          (probe.kind === "dir" && stat.isDirectory());
        if (ok) addMatch(probe.profile, probe.reason);
      } catch {
        // marker not present
      }
    }

    // Refine using package.json contents (deps / bin / contributes / mcp dep).
    const parsed = await this.parsePackageJson(repoLocalPath);
    if (parsed) {
      if (parsed.isMcp) addMatch("mcp", 'package.json depends on "@modelcontextprotocol"');
      if (parsed.isVscodeExtension) addMatch("vscode_extension", 'package.json has "contributes"');
      if (parsed.isCli) addMatch("cli", 'package.json declares a "bin" entry');
      if (parsed.isFrontend) addMatch("frontend", "package.json depends on react / vite / next");
      if (parsed.isSdk)
        addMatch(
          "sdk",
          'package.json is a publishable library (has "exports"/"types", no app entry)',
        );
      if (parsed.isBackend)
        addMatch(
          "backend",
          "package.json depends on a server framework (elysia / express / fastify / apollo)",
        );
    }

    // GitOps: an IaC-shaped repo that is purely declarative manifests with an
    // argocd/flux marker is a gitops tree rather than a module to build.
    if (byProfile.has("iac")) {
      for (const marker of ["argocd", ".argocd", "flux-system", "clusters"]) {
        try {
          const stat = await fs.stat(path.join(repoLocalPath, marker));
          if (stat.isDirectory()) {
            addMatch("gitops", `${marker}/ directory (GitOps tree)`);
            break;
          }
        } catch {
          // not present
        }
      }
    }

    const profiles = [...byProfile.values()].sort(
      (a, b) => PRIMARY_PRECEDENCE.indexOf(a.profile) - PRIMARY_PRECEDENCE.indexOf(b.profile),
    );

    const primary =
      PRIMARY_PRECEDENCE.find((p) => byProfile.has(p)) ?? profiles[0]?.profile ?? "unknown";

    const ownership = this.readOwnership(input);

    return { profiles, primary, ownership };
  }

  private async parsePackageJson(repoLocalPath: string): Promise<ParsedPackageJson | null> {
    let raw: string;
    try {
      raw = await fs.readFile(path.join(repoLocalPath, "package.json"), "utf-8");
    } catch {
      return null;
    }
    let pkg: Record<string, unknown>;
    try {
      pkg = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      this.host?.logger?.warn?.("repo-profile-detector", "package.json present but not valid JSON");
      return null;
    }

    const deps = collectDependencyNames(pkg);
    const has = (name: string): boolean => deps.has(name);
    const hasPrefix = (prefix: string): boolean => {
      for (const d of deps) if (d.startsWith(prefix)) return true;
      return false;
    };

    const isMcp = has("@modelcontextprotocol/sdk") || hasPrefix("@modelcontextprotocol/");
    const isVscodeExtension =
      isRecord(pkg.contributes) || (isRecord(pkg.engines) && "vscode" in pkg.engines);
    const isCli = pkg.bin !== undefined;
    const isFrontend =
      has("react") || has("vite") || has("next") || has("@angular/core") || has("vue");
    const isBackend =
      has("elysia") ||
      has("express") ||
      has("fastify") ||
      has("@apollo/server") ||
      has("graphql-yoga") ||
      has("@nestjs/core") ||
      has("koa");
    // A library/SDK: publishable (has exports/types) without an app entry and
    // without a CLI bin.
    const isSdk =
      !isCli &&
      !isFrontend &&
      (pkg.exports !== undefined || pkg.types !== undefined || pkg.typings !== undefined) &&
      pkg.private !== true;

    return { isFrontend, isCli, isMcp, isVscodeExtension, isSdk, isBackend };
  }

  private readOwnership(input: SecurityScanInput): OwnershipMeta {
    const cfg = input.config ?? {};
    const owner = pickString(cfg, ["owner", "ownerTeam", "team"]);
    const criticality = pickString(cfg, ["criticality", "tierName"]);
    const tierRaw = cfg.tier;
    const tier =
      typeof tierRaw === "number"
        ? tierRaw
        : typeof tierRaw === "string" && /^\d+$/.test(tierRaw)
          ? Number.parseInt(tierRaw, 10)
          : undefined;
    return { owner, criticality, tier };
  }

  // ── Recommendation + persistence ──────────────────────────────────────

  private buildRecommendation(
    detection: DetectionResult,
    input: SecurityScanInput,
  ): {
    enabledStages: SecurityStage[];
    policyLevel: SecurityPolicyLevel;
    profileSummary: { primary: string; profiles: RepoProfile[] };
    perProfileStages: Record<string, SecurityStage[]>;
  } {
    const stageSet = new Set<SecurityStage>(BASELINE_STAGES);
    const perProfileStages: Record<string, SecurityStage[]> = {};

    for (const match of detection.profiles) {
      const extras = PROFILE_STAGE_EXTRAS[match.profile];
      perProfileStages[match.profile] = [...BASELINE_STAGES, ...extras];
      for (const s of extras) stageSet.add(s);
    }

    // Stable, lifecycle-ordered stage list.
    const enabledStages = ALL_STAGES_ORDER.filter((s) => stageSet.has(s));

    const policyLevel = this.derivePolicyLevel(detection.ownership, input);

    return {
      enabledStages,
      policyLevel,
      profileSummary: {
        primary: detection.primary,
        profiles: detection.profiles.map((p) => p.profile),
      },
      perProfileStages,
    };
  }

  /**
   * tier_0 / tier_1 → block, tier_2 → warn, tier_3+ → advisory
   * (stage-01 spec). When criticality is unknown we default to `warn`
   * (tier_2 / "standard"), the safe middle ground.
   */
  private derivePolicyLevel(
    ownership: OwnershipMeta,
    input: SecurityScanInput,
  ): SecurityPolicyLevel {
    if (typeof ownership.tier === "number") {
      if (ownership.tier <= 1) return "block";
      if (ownership.tier === 2) return "warn";
      return "advisory";
    }
    const c = ownership.criticality?.toLowerCase();
    if (c) {
      if (c.includes("critical") || c === "tier_0" || c === "tier_1" || c === "high")
        return "block";
      if (c.includes("standard") || c === "tier_2" || c === "medium") return "warn";
      if (c.includes("low") || c === "tier_3" || c === "tier_4") return "advisory";
    }
    // No criticality signal — honour an explicit per-run policy if provided,
    // else fall back to the standard tier_2 default.
    return input.policyLevel ?? "warn";
  }

  private async persistConfig(
    input: SecurityScanInput,
    rec: ReturnType<RepoProfileDetectorProvider["buildRecommendation"]>,
  ): Promise<{ persisted: boolean; detail: string }> {
    if (!this.host?.workspaceQuery) {
      return {
        persisted: false,
        detail: "host has no workspaceQuery; recommendation surfaced as evidence only",
      };
    }
    const input_ = {
      enabledStages: rec.enabledStages.map((s) => GQL_STAGES[s]),
      policyLevel: GQL_POLICY_LEVELS[rec.policyLevel],
      pluginAssignments: {},
      configYamlEquivalent: {
        onboard: {
          version: PROFILE_VERSION,
          profile: rec.profileSummary,
          enabledStages: rec.enabledStages,
          perProfileStages: rec.perProfileStages,
          policyLevel: rec.policyLevel,
        },
      },
    };
    try {
      const res = await this.host.workspaceQuery<{
        updateRepositorySecurityConfig: { id: string; policyLevel: string } | null;
      }>(UPDATE_CONFIG_MUTATION, { vibeId: input.vibeId, input: input_ });
      if (res.errors && res.errors.length > 0) {
        const detail = res.errors.map((e) => e.message).join("; ");
        this.host.logger?.warn?.(
          "repo-profile-detector",
          `config persist returned errors: ${detail}`,
        );
        return { persisted: false, detail: `backend errors: ${detail}` };
      }
      if (!res.data?.updateRepositorySecurityConfig) {
        return { persisted: false, detail: "backend returned no config row" };
      }
      return {
        persisted: true,
        detail: `persisted RepositorySecurityConfig ${res.data.updateRepositorySecurityConfig.id}`,
      };
    } catch (err) {
      this.host.logger?.warn?.("repo-profile-detector", `config persist failed: ${String(err)}`);
      return { persisted: false, detail: `persist failed: ${String(err)}` };
    }
  }

  // ── Findings + evidence ───────────────────────────────────────────────

  private buildFindings(
    input: SecurityScanInput,
    detection: DetectionResult,
    rec: ReturnType<RepoProfileDetectorProvider["buildRecommendation"]>,
    persistence: { persisted: boolean; detail: string },
  ): NormalizedFinding[] {
    const findings: NormalizedFinding[] = [];

    if (detection.profiles.length === 0) {
      findings.push({
        fingerprint: this.fp(input.runId, "no-profile"),
        ruleId: `${this.name}.profile-unknown`,
        title: "repo.onboard: no recognized repo profile detected",
        severity: "info",
        category: "config",
        description:
          "No recognized marker files (package.json, go.mod, Cargo.toml, Dockerfile, *.tf, Chart.yaml, manifest.json, mcp.json, capacitor.config.*, src/extension.ts, …) were found. Defaulting to the baseline security stages.",
        remediation:
          "Add a profile hint in the Security tab if this repo is something the detector should recognize.",
        rawProviderRef: JSON.stringify({
          detectedProfiles: [],
          enabledStages: rec.enabledStages,
          policyLevel: rec.policyLevel,
          configPersisted: persistence.persisted,
        }),
      });
    }

    for (const match of detection.profiles) {
      const stages = rec.perProfileStages[match.profile] ?? rec.enabledStages;
      const isPrimary = match.profile === detection.primary;
      findings.push({
        fingerprint: this.fp(input.runId, `profile:${match.profile}`),
        ruleId: `${this.name}.profile-detected`,
        title: `repo.onboard: detected ${isPrimary ? "primary " : ""}profile = ${match.profile}`,
        severity: "info",
        category: "config",
        description: `Detected via: ${match.reasons.join("; ")}. Recommended lifecycle stages: ${stages.join(", ")}.`,
        remediation: `Enable the recommended stages for the ${match.profile} profile in the Security tab (policy level: ${rec.policyLevel}).`,
        rawProviderRef: JSON.stringify({
          profile: match.profile,
          isPrimary,
          reasons: match.reasons,
          recommendedStages: stages,
          policyLevel: rec.policyLevel,
          configPersisted: persistence.persisted,
          persistenceDetail: persistence.detail,
        }),
      });
    }

    // Ownership / criticality gap — blocking-eligible (medium) per spec.
    const { owner, criticality, tier } = detection.ownership;
    if (!owner || (criticality === undefined && tier === undefined)) {
      const missing: string[] = [];
      if (!owner) missing.push("owner/team");
      if (criticality === undefined && tier === undefined) missing.push("criticality/tier");
      findings.push({
        fingerprint: this.fp(input.runId, "ownership-missing"),
        ruleId: `${this.name}.ownership-missing`,
        title: `repo.onboard: missing ${missing.join(" + ")} metadata`,
        severity: "medium",
        category: "policy",
        description: `This repo has no ${missing.join(" and no ")} set. Criticality drives the default policy level (tier_0/1 → block, tier_2 → warn, tier_3+ → advisory); without it onboarding fell back to policyLevel="${rec.policyLevel}".`,
        remediation:
          "Set the owning team and a criticality tier on the Vibe so release gating uses the correct policy level.",
        rawProviderRef: JSON.stringify({
          missing,
          appliedPolicyLevel: rec.policyLevel,
        }),
      });
    }

    return findings;
  }

  private async writeEvidence(
    input: SecurityScanInput,
    detection: DetectionResult,
    rec: ReturnType<RepoProfileDetectorProvider["buildRecommendation"]>,
    persistence: { persisted: boolean; detail: string },
  ): Promise<ScanEvidenceArtifact> {
    const payload = {
      schema: "vibecontrols.security.onboard/v2",
      generatedAt: new Date().toISOString(),
      toolVersion: this.toolVersion,
      vibeId: input.vibeId,
      workspaceId: input.workspaceId,
      repoUrl: input.repoUrl,
      commit: input.commit,
      detection: {
        primary: detection.primary,
        profiles: detection.profiles,
        ownership: detection.ownership,
      },
      recommendation: {
        enabledStages: rec.enabledStages,
        perProfileStages: rec.perProfileStages,
        policyLevel: rec.policyLevel,
      },
      persistence,
    };
    const json = `${JSON.stringify(payload, null, 2)}\n`;
    const outPath = path.join(input.workdir, "onboard-profile.json");
    await fs.writeFile(outPath, json, "utf-8");
    const stat = await fs.stat(outPath);
    return {
      type: "opa-decision",
      localPath: outPath,
      sha256: createHash("sha256").update(json).digest("hex"),
      sizeBytes: stat.size,
    };
  }

  private summarize(findings: NormalizedFinding[]): SecurityScanSummary {
    const summary: SecurityScanSummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) summary[f.severity] += 1;
    return summary;
  }

  private fp(runId: string, key: string): string {
    return createHash("sha256").update(`${this.name}:${runId}:${key}`).digest("hex");
  }
}

// ── Pure helpers ──────────────────────────────────────────────────────────

const ALL_STAGES_ORDER: readonly SecurityStage[] = [
  "repo.onboard",
  "developer.local",
  "pull_request.fast",
  "pull_request.deep",
  "main.merge",
  "build",
  "package.publish",
  "deploy.preview",
  "deploy.alpha",
  "promote.prod",
  "runtime.continuous",
  "scheduled.rescan",
  "incident.response",
  "archive.offboard",
];

async function readdirSafe(dir: string): Promise<string[]> {
  try {
    return await fs.readdir(dir);
  } catch {
    return [];
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function collectDependencyNames(pkg: Record<string, unknown>): Set<string> {
  const names = new Set<string>();
  for (const field of [
    "dependencies",
    "devDependencies",
    "peerDependencies",
    "optionalDependencies",
  ]) {
    const block = pkg[field];
    if (isRecord(block)) {
      for (const name of Object.keys(block)) names.add(name);
    }
  }
  return names;
}

function pickString(obj: Record<string, unknown>, keys: readonly string[]): string | undefined {
  for (const key of keys) {
    const v = obj[key];
    if (typeof v === "string" && v.trim().length > 0) return v.trim();
  }
  return undefined;
}

/** Translate a simple `*.ext` glob to an anchored RegExp (only `*` supported). */
function globToRegExp(glob: string): RegExp {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*");
  return new RegExp(`^${escaped}$`);
}
