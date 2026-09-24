/**
 * How the evidence was held, in words: the guard each pane or VM actually
 * got, and a name whose bytes are not UTF-8 shown as bytes. Pure: the
 * Inputs tab and the Goal tab use it, and node tests import it.
 */
import type { InputsView, VmHealth } from "./types.ts";

export type GuardSummary = { text: string; tone: "kelp" | "saffron" | "brick" };

export function guardWord(guard: string): string {
  if (guard === "seatbelt") return "kernel (macOS sandbox-exec)";
  if (guard === "mountns") return "kernel (Linux mount namespace)";
  if (guard === "microvm") return "a read-only mount in each microVM";
  return "detect + heal";
}

/** A VM run's evidence guard, from each VM's probe: the mount is the guard. */
export function vmInputsSummary(vms: ReadonlyArray<Pick<VmHealth, "probe_checks">>): GuardSummary {
  if (!vms.length) return { text: "a read-only mount in each microVM", tone: "kelp" };
  const bad = vms.filter((vm) => (vm.probe_checks ?? []).some((c) => (c.check === "inputs/" || c.check === "the evidence executes") && !c.ok));
  if (bad.length) return { text: `read-only check failed in ${bad.length} VM${bad.length === 1 ? "" : "s"}`, tone: "brick" };
  return { text: "read-only, no-exec in every agent's microVM", tone: "kelp" };
}

export function enforcedWord(enforced: string): GuardSummary {
  if (enforced === "kernel") return { text: "kernel", tone: "kelp" };
  if (enforced === "mode") return { text: "permission bits", tone: "saffron" };
  return { text: "none", tone: "brick" };
}

export function inputsGuardSummary(inputs: InputsView): GuardSummary {
  const seen = Object.values(inputs.enforced);
  if (seen.length === 0) return { text: inputs.guard === "none" ? "detect + heal" : `${guardWord(inputs.guard)} planned`, tone: inputs.guard === "none" ? "saffron" : "kelp" };
  if (inputs.guard === "microvm" && seen.every((v) => v === "kernel")) return { text: "read-only in every agent's microVM", tone: "kelp" };
  if (seen.every((v) => v === "kernel")) return { text: "kernel in every pane", tone: "kelp" };
  if (seen.some((v) => v === "kernel")) return { text: "kernel in some panes", tone: "saffron" };
  return { text: "detect + heal only", tone: "saffron" };
}

/** A name whose bytes are not UTF-8, as bytes a reader can see: printable ASCII as is, the rest as \xHH. */
export function escapedName(b64: string): string {
  try {
    const raw = atob(b64);
    let out = "";
    for (let i = 0; i < raw.length; i++) {
      const c = raw.charCodeAt(i);
      out += c >= 0x20 && c < 0x7f && c !== 0x5c ? raw[i] : `\\x${c.toString(16).padStart(2, "0")}`;
    }
    return out;
  } catch {
    return b64;
  }
}
