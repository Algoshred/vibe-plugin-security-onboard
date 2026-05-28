/**
 * @vibecontrols/vibe-plugin-security-onboard
 *
 * Repo profile detector. Registers as a `security.onboard`
 * provider with @vibecontrols/vibe-plugin-security on the host's
 * ServiceRegistry. When the user runs the onboard lifecycle stage
 * the security meta plugin dispatches detection to this provider
 * which walks marker files (package.json, go.mod, Cargo.toml,
 * Chart.yaml, manifest.json, pubspec.yaml, capacitor.config.*) and
 * emits a single info finding with the inferred profile in metadata.
 */
import { ProviderRegistry, TelemetryEmitter, createLifecycleHooks } from "@vibecontrols/plugin-sdk";
import type {
  HostServices,
  ProfileContext,
  VibePlugin,
  VibePluginFactory,
} from "@vibecontrols/plugin-sdk/contract";

import { RepoProfileDetectorProvider } from "./provider.js";

const PLUGIN_NAME = "security-onboard";
const PLUGIN_VERSION = "2026.528.1";

export const createPlugin: VibePluginFactory = (_ctx: ProfileContext): VibePlugin => {
  const provider = new RepoProfileDetectorProvider();
  const telemetry = new TelemetryEmitter(PLUGIN_NAME, PLUGIN_VERSION);

  const lifecycle = createLifecycleHooks({
    name: PLUGIN_NAME,
    telemetryEventName: "security.onboard.ready",
    onInit: async (host: HostServices) => {
      await provider.init(host);
      const registry = new ProviderRegistry(host);
      registry.registerProvider("security.onboard", "repo-profile-detector", provider);
      telemetry.emit("security.onboard.registered", {
        provider: "repo-profile-detector",
        toolVersion: provider.toolVersion,
      });
    },
  });

  return {
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    description: "Repo profile detector for the repo.onboard lifecycle stage.",
    tags: ["backend", "provider", "integration"],
    capabilities: {
      storage: "rw",
      audit: true,
      telemetry: true,
    },
    onServerStart: lifecycle.onServerStart,
    onServerStop: lifecycle.onServerStop,
  };
};

export default createPlugin;
export { RepoProfileDetectorProvider } from "./provider.js";
