# @vibecontrols/vibe-plugin-security-onboard

`@vibecontrols/vibe-plugin-security-onboard` serves the `repo.onboard` lifecycle stage. It registers itself with [`@vibecontrols/vibe-plugin-security`](https://www.npmjs.com/package/@vibecontrols/vibe-plugin-security) under the per-stage provider type `security.onboard` and the provider name `repo-profile-detector`. It is a pure-JS detector — it does **not** wrap an external binary — and walks the repo root for marker files (`package.json`, `go.mod`, `Cargo.toml`, `Chart.yaml`, `manifest.json`, `pubspec.yaml`, `capacitor.config.*`, `main.tf`) to infer whether the repo is `frontend` / `backend` / `cli` / `mcp` / `chrome-extension` / `vscode-extension` / `mobile` / `iac` / etc.

Wave 2 scaffold — real profile-classification model + policy seeding is pending; see `src/provider.ts` TODO.

## Install

```bash
vibe plugin install @vibecontrols/vibe-plugin-security-onboard
vibe security providers set-default --stage repo.onboard --provider repo-profile-detector
```

## Behavior

- Walks `repoLocalPath` for high-precedence marker files in order:
  - `capacitor.config.*`, `pubspec.yaml` → `mobile`
  - `manifest.json` → `chrome-extension`
  - `Chart.yaml`, `main.tf` → `iac`
  - `Cargo.toml` → `cli`
  - `go.mod`, `package.json` → `backend`
- Emits a single info finding with `category: "config"`, `ruleId: "repo-profile-detector.profile-detected"`.
- The detected profile + all matched markers are JSON-encoded in `rawProviderRef` for downstream policy seeders.

## Configuration

No per-vibe configuration is required. The detector is idempotent and side-effect-free.

## License

Proprietary — Burdenoff Consultancy Services Pvt. Ltd.
