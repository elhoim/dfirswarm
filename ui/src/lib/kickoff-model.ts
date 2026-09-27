/**
 * The kickoff form's model default, and what the microVM kickoff would
 * refuse about a provider. Pure: the form imports it, and node tests import
 * it as it is.
 */
import type { ProviderReadiness, VmBlocker } from "./types.ts";

export function providerOf(model: string): string {
  const slash = model.indexOf("/");
  return slash === -1 ? model : model.slice(0, slash);
}

/**
 * What the VM kickoff would still refuse about a provider, once the form's
 * own settings are counted: OAuth allowed in the VMs, a host named for it.
 */
export function activeVmBlockers(r: ProviderReadiness | undefined, allowOauth: boolean, named: ReadonlySet<string>): VmBlocker[] {
  return (r?.vm_blockers ?? []).filter((b) => !(b.lifted_by === "allow_oauth_in_vm" && allowOauth) && !(b.lifted_by === "provider_hosts" && named.has(r?.provider ?? "")));
}

/** The form's microVM settings that decide what a VM takes; null when the run is on the host. */
export type VmSettings = { allowOauth: boolean; named: ReadonlySet<string> } | null;

/**
 * The model the form should move to, or null to leave it as it is.
 *
 * The default is the first model whose provider is actually usable, not the
 * first in the list: a kickoff that swarm.sh would refuse is a bad default.
 * Under microVM, usable means the VM kickoff takes it too. On a host logged
 * in to one provider by subscription, "ready" alone picked that provider,
 * and a fresh form opened on the red "the VM kickoff would refuse" note
 * while a provider with an API key would have gone in. When no ready
 * provider is one a VM takes, the first ready one stands in, as before, and
 * the note says why. Until readiness answers, the first model stands in.
 *
 * A model the operator picked is never changed, and neither is a default
 * that is already usable: the default moves only to a better one.
 */
export function defaultModelMove(opts: {
  models: readonly string[];
  current: string;
  touched: boolean;
  providers: Record<string, ProviderReadiness> | undefined;
  vm: VmSettings;
}): string | null {
  const { models, current, touched, providers, vm } = opts;
  if (!models.length) return null;
  const ready = (m: string) => providers?.[providerOf(m)]?.status === "ready";
  const usable = (m: string) => ready(m) && (!vm || activeVmBlockers(providers?.[providerOf(m)], vm.allowOauth, vm.named).length === 0);
  const pick = providers ? (models.find(usable) ?? models.find(ready)) : undefined;
  if (!current) return pick ?? models[0];
  if (touched || !pick || pick === current || usable(current)) return null;
  // Ready on the host and refused by the VM either way: nothing gained.
  if (!usable(pick) && ready(current)) return null;
  return pick;
}
