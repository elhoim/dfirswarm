#!/usr/bin/env node
/**
 * The case policy: what an examination permits to leave the run, to reach
 * outside it and to come into it, set once at kickoff and recorded with the
 * run (docs/adr/0014, the case contract).
 *
 * Two controls, kept apart (docs/adr/0012). The run's **network mode** says
 * how access is decided: `closed` (today's default: the models' hosts, the
 * package index when installs are allowed, and the operator's own hosts),
 * `dynamic` (an agent asks, the hub decides under this policy, a host-side
 * fetch service carries it out) or `open` (every public host, as
 * `--no-netguard` has always meant). The **case policy** says what the
 * examination permits whatever the mode: which lookups, whether the subject's
 * infrastructure may be contacted, which classes of case data may leave, the
 * legal text the operator fills in, what the operator knows of the
 * providers' retention, whether more evidence may arrive while the run goes
 * on (`more_evidence`: no, ask or yes), and what each class of material that
 * enters from outside the evidence may be used for (`material_use`). An agent
 * can weaken neither: both are the kickoff's, recorded in
 * `network/policy.json`, SWARM.md and the run's registry record, anchored
 * beside the run and sealed by custody, and read on every decision.
 *
 * A preset sets every field; the goal's metadata block and the kickoff's
 * flags override single fields; a combination that contradicts its preset or
 * itself is refused at kickoff, never resolved by guessing. A run that says
 * nothing is `standard` with the network `closed`, which is what every run
 * was before this module: nothing changes for it. A resumed run keeps the
 * policy its kickoff recorded.
 *
 *   node --experimental-strip-types scripts/case-policy.ts resolve [--goal-file F]
 *        [--policy P] [--network M] [--lookups L] [--contact C] [--disclosure LIST]
 *        [--more-evidence no|ask|yes] [--material-use SPEC] [--legal TEXT]
 *        [--provider-retention TEXT] [--legacy-open] [--isolation microvm|host]
 *        [--allow-hosts LIST]
 *   node --experimental-strip-types scripts/case-policy.ts check-egress --policy-json JSON
 *        [--allow-hosts LIST] [--install-hosts LIST] [--pack-hosts LIST]
 *   node --experimental-strip-types scripts/case-policy.ts services --goal-file F --policy-json JSON
 *        the services the goal names, held to the policy and the adapter catalogue (warnings)
 *   node --experimental-strip-types scripts/case-policy.ts show <sandbox>
 *   node --experimental-strip-types scripts/case-policy.ts compare <sandbox> --policy-json JSON
 *        a resumed run's recorded policy against what its options resolve to now
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const PRESETS = ["standard", "live_adversary", "internal", "ctf"] as const;
export type Preset = (typeof PRESETS)[number];
export const NETWORK_MODES = ["closed", "dynamic", "open"] as const;
export type NetworkMode = (typeof NETWORK_MODES)[number];
/** What the hub may grant by itself: nothing, reference data, reference and evidence-linked lookups, or any lookup. */
export const LOOKUPS = ["none", "reference", "evidence_linked", "any"] as const;
export type Lookups = (typeof LOOKUPS)[number];
/** Whether the subject's own infrastructure may be contacted (an evidence URL's HEAD, a live DNS lookup of a suspect name). */
export const CONTACT = ["passive", "active"] as const;
export type Contact = (typeof CONTACT)[number];
/** The classes of case data a request can carry out of the run. */
export const DISCLOSURE_CLASSES = ["hash", "public_indicator", "coordinate", "internal_name", "personal", "file_upload"] as const;
export type DisclosureClass = (typeof DISCLOSURE_CLASSES)[number];
/**
 * Whether more evidence may arrive while the run goes on: `no` (a closed
 * collection or a published case: an acquisition ask is answered at once,
 * "no additional input under this case policy"), `ask` (the operator decides
 * each ask) or `yes` (further collection is expected: an ask is authorised
 * by the policy, and the operator collects it).
 */
export const MORE_EVIDENCE = ["no", "ask", "yes"] as const;
export type MoreEvidence = (typeof MORE_EVIDENCE)[number];
/**
 * Where material that entered the run from outside the original evidence
 * came from: evidence acquired after the kickoff (`swarm.sh evidence add`),
 * case material (an intake note, a statement, a policy document), material
 * the operator supplied (a question's attachment, `swarm.sh material add`),
 * and a capture the fetch service sealed. The ledger's `external` kind
 * carries the same classes (extensions/protocol.ts LEDGER_SOURCE_CLASSES).
 */
export const SOURCE_CLASSES = ["acquired_evidence", "case_material", "operator_supplied", "external_capture"] as const;
export type SourceClass = (typeof SOURCE_CLASSES)[number];
/**
 * What a class of material may be used for: `evidence` (a finding may rest
 * on it as it rests on the original evidence; it is still named as material
 * from outside the original set), `reference` (it may be cited; what rests
 * on it is flagged, and an examiner records what it establishes) or `none`
 * (it is kept on the record and may not be cited).
 */
export const MATERIAL_USES = ["evidence", "reference", "none"] as const;
export type MaterialUseLevel = (typeof MATERIAL_USES)[number];
export type MaterialUse = Record<SourceClass, MaterialUseLevel>;

/** Where a field's value came from. */
export type Source = "preset" | "goal" | "flag" | "legacy" | "default";

export type CasePolicy = {
  /** 2: material_use is a map from source class to use (1, a text, is still read). */
  v: 1 | 2;
  policy: Preset;
  network: NetworkMode;
  lookups: Lookups;
  contact: Contact;
  /** Each class of case data: may it leave the run. */
  disclosure: Record<DisclosureClass, "allow" | "deny">;
  /**
   * Whether a request must show that what it sends out is in the evidence:
   * `active_only` asks it of evidence-linked (active) requests alone,
   * `required` of every request (a published case: the question text can
   * never be what is looked up).
   */
  evidence_link: "active_only" | "required";
  /**
   * How active contact is decided when `contact` allows it: `evidence_linked`
   * (the hub grants an evidence-linked adapter by itself), `operator` (every
   * one is an operator item) or `never` (refused, and the operator cannot
   * grant it without changing the case policy).
   */
  active_contact: "evidence_linked" | "operator" | "never";
  /** Socket grants (tier 2: host and port only, no content capture): the operator may make them, or nobody may. */
  sockets: "operator" | "none";
  /** Whether the operator may override a category denial (search, write-up, paste, social, proxy). Logins, uploads and credentials never. */
  category_override: boolean;
  /** An LLM steward that may only narrow a decision. Not built; always off, and off by rule under ctf. */
  steward: "off";
  /** The operator's legal text (jurisdiction, warrant scope, "GDPR or similar laws"): recorded, never inferred. */
  legal: string;
  /** What the operator knows of how the model and lookup providers keep what they are sent. */
  provider_retention: string;
  /** Whether more evidence may arrive during the run (the acquisition lane). */
  more_evidence: MoreEvidence;
  /** What each class of material from outside the original evidence may be used for. */
  material_use: MaterialUse;
  /** What the preset says of material beyond the map (a published case's write-ups are never material). */
  material_note: string;
  sources: Record<string, Source>;
};

type PresetBody = Omit<CasePolicy, "v" | "policy" | "network" | "sources" | "legal" | "provider_retention"> & { network?: NetworkMode };

const allow = (...classes: DisclosureClass[]): Record<DisclosureClass, "allow" | "deny"> =>
  Object.fromEntries(DISCLOSURE_CLASSES.map((c) => [c, classes.includes(c) ? "allow" : "deny"])) as Record<DisclosureClass, "allow" | "deny">;

/** Evidence acquired later is evidence; everything else from outside is reference material. */
const REFERENCE_USE: MaterialUse = { acquired_evidence: "evidence", case_material: "reference", operator_supplied: "reference", external_capture: "reference" };

/**
 * The four presets (the owner's decision of 2026-09-28: `standard` by
 * default). `standard`: only hashes and public indicators, to approved
 * passive adapters; active contact is the operator's. `live_adversary`:
 * stricter, no contact with anything the evidence names, at all.
 * `internal`: nothing leaves, and nothing is captured from outside.
 * `ctf`: a published case, where write-ups exist: no search, no write-up
 * site, only reference or evidence-linked adapters, whatever is sent must be
 * in the evidence, and no evidence arrives after the kickoff.
 */
export const PRESET: Record<Preset, PresetBody> = {
  standard: {
    lookups: "reference",
    contact: "passive",
    disclosure: allow("hash", "public_indicator"),
    evidence_link: "active_only",
    active_contact: "operator",
    sockets: "operator",
    category_override: true,
    steward: "off",
    more_evidence: "ask",
    material_use: { ...REFERENCE_USE },
    material_note: "an examiner records what a capture or supplied material establishes",
  },
  live_adversary: {
    lookups: "reference",
    contact: "passive",
    disclosure: allow("hash", "public_indicator"),
    evidence_link: "active_only",
    active_contact: "never",
    sockets: "none",
    category_override: true,
    steward: "off",
    more_evidence: "ask",
    material_use: { ...REFERENCE_USE },
    material_note: "an examiner records what a capture or supplied material establishes",
  },
  internal: {
    network: "closed",
    lookups: "none",
    contact: "passive",
    disclosure: allow(),
    evidence_link: "required",
    active_contact: "never",
    sockets: "none",
    category_override: false,
    steward: "off",
    more_evidence: "ask",
    material_use: { ...REFERENCE_USE, external_capture: "none" },
    material_note: "nothing leaves the run, and nothing is captured from outside it",
  },
  ctf: {
    lookups: "evidence_linked",
    contact: "active",
    disclosure: allow("hash", "public_indicator", "coordinate"),
    evidence_link: "required",
    active_contact: "evidence_linked",
    sockets: "none",
    category_override: false,
    steward: "off",
    more_evidence: "no",
    material_use: { ...REFERENCE_USE },
    material_note: "an examiner records what a capture establishes; a published case's write-ups are never material",
  },
};

/** What each use means, in words. */
export const USE_WORDS: Record<MaterialUseLevel, string> = {
  evidence: "a finding may rest on it as on the original evidence, named as material from outside the original set",
  reference: "it may be cited; what rests on it is flagged, and an examiner records what it establishes",
  none: "kept on the record; an agent's record may not cite it",
};

/** Whether more evidence may come, in words: what the hub does with an acquisition ask. */
export const MORE_EVIDENCE_WORDS: Record<MoreEvidence, string> = {
  no: `no further evidence during this run: an acquisition ask is answered at once, "${"no additional input under this case policy"}", a constraint of this case and never a finding that something is absent`,
  ask: "an acquisition ask goes to the operator, who authorises or declines it",
  yes: "further evidence is expected: an acquisition ask is authorised by this policy, and the operator collects it",
};

/** The words the hub answers an acquisition ask with under `more_evidence: no`. Never "the fact is absent". */
export const NO_MORE_EVIDENCE_ANSWER = "no additional input under this case policy";

/** The use a class of material has under a policy, as a provenance record states it. */
export function permittedUse(p: CasePolicy, cls: SourceClass): string {
  const use = p.material_use[cls];
  return `${use}: ${USE_WORDS[use]}`;
}

/**
 * A material-use text as the goal's metadata block or the kickoff gives it:
 * `class=use` pairs (`,` or space between them), each class one of
 * SOURCE_CLASSES and each use one of MATERIAL_USES; a class left out keeps
 * the preset's use. What does not parse is said, never guessed.
 */
export function parseMaterialUse(text: string, base: MaterialUse): { ok: true; use: MaterialUse } | { ok: false; reason: string } {
  const out: MaterialUse = { ...base };
  const parts = text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean);
  if (!parts.length) return { ok: false, reason: `material_use is class=use pairs (${SOURCE_CLASSES.join(", ")}; ${MATERIAL_USES.join(", ")})` };
  for (const part of parts) {
    const m = /^([a-z_]+)\s*[=:]\s*([a-z]+)$/.exec(part.toLowerCase());
    if (!m) return { ok: false, reason: `material_use: ${JSON.stringify(part)} is not class=use (for example external_capture=reference); the classes are ${SOURCE_CLASSES.join(", ")}, the uses ${MATERIAL_USES.join(", ")}` };
    if (!(SOURCE_CLASSES as readonly string[]).includes(m[1])) return { ok: false, reason: `material_use: ${m[1]} is not a class (${SOURCE_CLASSES.join(", ")})` };
    if (!(MATERIAL_USES as readonly string[]).includes(m[2])) return { ok: false, reason: `material_use: ${m[2]} is not a use (${MATERIAL_USES.join(", ")})` };
    out[m[1] as SourceClass] = m[2] as MaterialUseLevel;
  }
  return { ok: true, use: out };
}

/** A material-use map as text, the form parseMaterialUse reads. */
export function materialUseText(u: MaterialUse): string {
  return SOURCE_CLASSES.map((c) => `${c}=${u[c]}`).join(", ");
}

/** The policy of a run that says nothing: standard, with the network closed. */
export function defaultPolicy(): CasePolicy {
  return build("standard", {}, {});
}

function build(preset: Preset, overrides: Partial<Record<string, string>>, from: Record<string, Source>, materialUse?: MaterialUse): CasePolicy {
  const p = PRESET[preset];
  const sources: Record<string, Source> = { policy: from.policy ?? "default" };
  const pick = <T extends string>(key: string, fallback: T): T => {
    const v = overrides[key];
    if (v !== undefined) {
      sources[key] = from[key] ?? "flag";
      return v as T;
    }
    sources[key] = key in p ? "preset" : "default";
    return fallback;
  };
  const disclosureText = overrides.disclosure;
  let disclosure = { ...p.disclosure };
  if (disclosureText !== undefined) {
    disclosure = allow(...(disclosureText.split(/[\s,]+/).filter(Boolean) as DisclosureClass[]));
    sources.disclosure = from.disclosure ?? "flag";
  } else sources.disclosure = "preset";
  if (materialUse) sources.material_use = from.material_use ?? "flag";
  else sources.material_use = "preset";
  return {
    v: 2,
    policy: preset,
    network: pick<NetworkMode>("network", p.network ?? "closed"),
    lookups: pick<Lookups>("lookups", p.lookups),
    contact: pick<Contact>("contact", p.contact),
    disclosure,
    evidence_link: p.evidence_link,
    active_contact: p.active_contact,
    sockets: p.sockets,
    category_override: p.category_override,
    steward: "off",
    legal: pick<string>("legal", ""),
    provider_retention: pick<string>("provider_retention", ""),
    more_evidence: pick<MoreEvidence>("more_evidence", p.more_evidence),
    material_use: materialUse ?? { ...p.material_use },
    material_note: p.material_note,
    sources,
  };
}

/** The keys the goal's metadata block and the kickoff may set. */
export const POLICY_KEYS = ["policy", "network", "lookups", "contact", "disclosure", "legal", "provider_retention", "more_evidence", "material_use"] as const;

/** The kickoff flag of each key (swarm.sh start). */
export const POLICY_FLAGS: Record<(typeof POLICY_KEYS)[number], string> = {
  policy: "--policy",
  network: "--network",
  lookups: "--lookups",
  contact: "--contact",
  disclosure: "--disclosure",
  legal: "--legal",
  provider_retention: "--provider-retention",
  more_evidence: "--more-evidence",
  material_use: "--material-use",
};

/**
 * The case-policy keys of a goal's metadata block (the `---` block a library
 * entry opens with), each value as written. A goal with no block, or none of
 * these keys, gives {}.
 */
export function goalPolicyKeys(text: string): Record<string, string> {
  const m = /^---[ \t]*\r?\n([\s\S]*?)\r?\n---[ \t]*(?:\r?\n|$)/.exec(text);
  if (!m) return {};
  const out: Record<string, string> = {};
  for (const line of m[1].split(/\r?\n/)) {
    const kv = /^([a-z_]+):[ \t]*(.*?)[ \t]*$/.exec(line);
    if (kv && (POLICY_KEYS as readonly string[]).includes(kv[1]) && kv[2] !== "") out[kv[1]] = kv[2];
  }
  return out;
}

export type ResolveInput = {
  /** The goal's metadata block's keys (goalPolicyKeys). */
  goal?: Record<string, string>;
  /** The kickoff's flags, by key. */
  flags?: Record<string, string>;
  /** --no-netguard: every public host, which is the `open` mode. */
  legacyOpen?: boolean;
  isolation?: "microvm" | "host";
  /** The kickoff's --allow-host entries: static socket allowances for the whole run. */
  allowHosts?: string[];
};

export type Resolution = { ok: true; policy: CasePolicy; notes: string[] } | { ok: false; conflicts: string[]; notes: string[] };

/** The free-text keys: kept as written, never lowered. */
const TEXT_KEYS = ["legal", "provider_retention", "material_use", "disclosure"];

/**
 * The run's case policy from its flags, its goal and its preset, or the
 * conflicts that stop the kickoff. Each value is checked against its
 * vocabulary, and the combination against its preset and itself: an
 * internal case cannot look anything up, a published case cannot be open or
 * receive evidence later, a capture is never evidence of the events, and so
 * on.
 */
export function resolveCasePolicy(input: ResolveInput): Resolution {
  const goal = input.goal ?? {};
  const flags = input.flags ?? {};
  const conflicts: string[] = [];
  const notes: string[] = [];
  const from: Record<string, Source> = {};
  const merged: Record<string, string> = {};
  for (const k of POLICY_KEYS) {
    if (flags[k] !== undefined && flags[k] !== "") {
      merged[k] = flags[k];
      from[k] = "flag";
      if (goal[k] !== undefined && goal[k] !== flags[k]) notes.push(`${k}: the kickoff's ${flags[k]} overrides the goal's ${goal[k]}`);
    } else if (goal[k] !== undefined && goal[k] !== "") {
      merged[k] = goal[k];
      from[k] = "goal";
    }
  }
  for (const k of POLICY_KEYS) if (merged[k] !== undefined && !TEXT_KEYS.includes(k)) merged[k] = merged[k].toLowerCase();
  const where = (k: string) => (from[k] === "goal" ? "the goal's metadata block" : `the kickoff's ${POLICY_FLAGS[k as (typeof POLICY_KEYS)[number]] ?? "flag"}`);
  const check = (k: string, vocab: readonly string[]) => {
    if (merged[k] !== undefined && !vocab.includes(merged[k])) conflicts.push(`${k}: ${JSON.stringify(merged[k])} is not one of ${vocab.join(", ")} (${where(k)})`);
  };
  check("policy", PRESETS);
  check("network", NETWORK_MODES);
  check("lookups", LOOKUPS);
  check("contact", CONTACT);
  check("more_evidence", MORE_EVIDENCE);
  if (merged.disclosure !== undefined) {
    const classes = merged.disclosure.split(/[\s,]+/).map((c) => c.toLowerCase()).filter(Boolean);
    const bad = classes.filter((c) => c !== "none" && !(DISCLOSURE_CLASSES as readonly string[]).includes(c));
    if (bad.length) conflicts.push(`disclosure: ${bad.join(", ")} ${bad.length === 1 ? "is not a class" : "are not classes"} (${DISCLOSURE_CLASSES.join(", ")}, or none)`);
    merged.disclosure = classes.filter((c) => c !== "none").join(",");
  }
  for (const k of ["legal", "provider_retention", "material_use"]) {
    if (merged[k] !== undefined && merged[k].length > 2000) conflicts.push(`${k} is over 2000 characters: nothing is cut, so a longer text is refused`);
  }
  // --no-netguard is the open mode; said against another mode, it contradicts it.
  if (input.legacyOpen) {
    if (merged.network !== undefined && merged.network !== "open") conflicts.push(`--no-netguard opens every public host, which contradicts network: ${merged.network}; drop one of them`);
    else if (merged.network === undefined) {
      merged.network = "open";
      from.network = "legacy";
    }
  }
  if (conflicts.length) return { ok: false, conflicts, notes };
  const preset = (merged.policy ?? "standard") as Preset;
  if (merged.policy !== undefined) from.policy = from.policy ?? "flag";
  let materialUse: MaterialUse | undefined;
  if (merged.material_use !== undefined) {
    const parsed = parseMaterialUse(merged.material_use, PRESET[preset].material_use);
    if (!parsed.ok) return { ok: false, conflicts: [`${parsed.reason} (${where("material_use")})`], notes };
    materialUse = parsed.use;
  }
  const overrides: Record<string, string> = { ...merged };
  delete overrides.policy;
  delete overrides.material_use;
  const policy = build(preset, overrides, from, materialUse);
  // The combination, against its preset.
  const allowed = DISCLOSURE_CLASSES.filter((c) => policy.disclosure[c] === "allow");
  if (preset === "internal") {
    if (policy.network === "open") conflicts.push("policy internal: nothing leaves the run, which contradicts network: open");
    if (policy.lookups !== "none") conflicts.push(`policy internal: nothing leaves the run, which contradicts lookups: ${policy.lookups}`);
    if (policy.contact !== "passive") conflicts.push("policy internal: nothing leaves the run, which contradicts contact: active");
    if (allowed.length) conflicts.push(`policy internal: nothing leaves the run, which contradicts disclosure: ${allowed.join(",")}`);
    if (policy.material_use.external_capture !== "none") notes.push(`policy internal: material_use external_capture=${policy.material_use.external_capture} is recorded, but nothing is captured from outside an internal case`);
  }
  if (preset === "ctf") {
    if (policy.network === "open") conflicts.push("policy ctf: every lookup of a published case goes through the fetch service (network: dynamic or closed), which contradicts network: open");
    if (policy.lookups === "any") conflicts.push("policy ctf: only reference or evidence-linked lookups, which contradicts lookups: any");
    for (const c of ["internal_name", "personal", "file_upload"] as const) if (policy.disclosure[c] === "allow") conflicts.push(`policy ctf: disclosure ${c} is not a published case's`);
    if (policy.more_evidence === "yes") conflicts.push("policy ctf: a published case's evidence is what was published, which contradicts more_evidence: yes (ask leaves each ask to the operator; no answers it at once)");
  }
  if (preset === "live_adversary") {
    if (policy.contact === "active") conflicts.push("policy live_adversary: nothing the evidence names is contacted, which contradicts contact: active");
    if (policy.network === "open") conflicts.push("policy live_adversary: every lookup is mediated, which contradicts network: open");
  }
  // The material use, against itself: a capture proves its bytes, never the events.
  if (policy.material_use.external_capture === "evidence") conflicts.push("material_use external_capture=evidence: a capture's hash proves its bytes, not their truth or their fit to the time of the events, so a capture is reference material at most (reference or none)");
  if (policy.more_evidence === "yes" && policy.material_use.acquired_evidence === "none") conflicts.push("more_evidence: yes with material_use acquired_evidence=none: evidence the run expects could never be cited; say more_evidence no or ask, or give acquired_evidence a use");
  if (policy.more_evidence === "no" && materialUse && policy.material_use.acquired_evidence !== PRESET[preset].material_use.acquired_evidence) notes.push("material_use acquired_evidence is recorded, but more_evidence: no admits no evidence after the kickoff");
  if (policy.disclosure.file_upload === "allow") notes.push("disclosure file_upload is recorded, but no adapter uploads: an upload stays refused by the hard denials");
  if (policy.lookups === "none" && policy.contact === "active") notes.push("contact: active with lookups: none grants nothing: no lookup is allowed");
  if (policy.network === "dynamic" && policy.lookups === "none") notes.push("network: dynamic with lookups: none grants nothing by itself: every lookup is the operator's item");
  if (policy.network === "dynamic" && input.isolation === "host") conflicts.push("network: dynamic needs the hub and the fetch service of a microVM run; a host run's network is closed or open (--no-netguard)");
  const hosts = (input.allowHosts ?? []).filter(Boolean);
  if (hosts.length && policy.sockets === "none") conflicts.push(`policy ${preset}: --allow-host ${hosts.join(",")} would be a socket allowance (host and port, no method or path control, no content capture), which this case policy does not permit; ${preset === "ctf" ? "a published case's lookups go through the fetch service (network: dynamic)" : "drop the host"}`);
  if (conflicts.length) return { ok: false, conflicts, notes };
  return { ok: true, policy, notes };
}

/**
 * The run's whole direct egress, held to its case policy: not only
 * `--allow-host`, but the package index `--allow-install` adds and the hosts
 * a pack's bound secrets go to. Each is a host a seat or a job reaches with
 * no grant, no disclosure check and no capture, so a policy that permits no
 * socket allowance (ctf, internal, live_adversary) refuses every one, naming
 * where it came from. The models' own hosts are the provider lane, not
 * research traffic, and are not held here.
 */
export function egressConflicts(p: CasePolicy, o: { allowHosts?: string[]; installHosts?: string[]; packHosts?: string[] }): string[] {
  if (p.sockets !== "none") return [];
  const out: string[] = [];
  const list = (xs?: string[]) => (xs ?? []).map((x) => x.trim()).filter(Boolean);
  const said = `policy ${p.policy} permits no direct host (host and port, no method or path control, no content capture): every request of this case is mediated`;
  if (list(o.allowHosts).length) out.push(`--allow-host ${list(o.allowHosts).join(",")}: ${said}`);
  if (list(o.installHosts).length) out.push(`--allow-install would open ${list(o.installHosts).join(", ")} to every VM and job: ${said}; add --no-pypi to keep the install machinery without the index, or drop --allow-install`);
  if (list(o.packHosts).length) out.push(`a pack's bound secrets would open ${[...new Set(list(o.packHosts))].join(", ")}: ${said}; run without --allow-pack-secrets`);
  return out;
}

/**
 * The generated VM spec and the job service's settings, held to the policy
 * they were made under: open egress (the spec's `open_net`, the jobs'
 * `openNet`) exactly when the network is `open`. A resume keeps its recorded
 * policy, and the start's own flags (`--no-netguard`) must not open what that
 * policy keeps closed, nor the other way round.
 */
export function specConflicts(p: CasePolicy | null, spec: { open_net?: unknown } | null, jobs: { openNet?: unknown } | null): string[] {
  if (!p) return [];
  const open = p.network === "open";
  const out: string[] = [];
  if (spec && typeof spec.open_net === "boolean" && spec.open_net !== open) out.push(`the VM spec says open_net ${spec.open_net}, and the case policy's network is ${p.network}${open ? "" : ": every VM would reach every public host"}`);
  if (jobs && typeof jobs.openNet === "boolean" && jobs.openNet !== open) out.push(`the job service's settings say openNet ${jobs.openNet}, and the case policy's network is ${p.network}${open ? "" : ": every job asking for network would reach every public host"}`);
  return out;
}

/** Where a run's case policy is recorded, and read on every network decision. */
export const POLICY_REL = "network/policy.json";

/**
 * A record read back: the current form from either version. A version 1
 * record's material_use was a text; it is read as class=use pairs when it is
 * one, else the preset's uses are taken and the text kept as the note.
 */
function normalise(raw: Partial<CasePolicy> & { material_use?: unknown }): CasePolicy {
  const preset = (PRESETS as readonly string[]).includes(String(raw.policy)) ? (raw.policy as Preset) : "standard";
  const base = build(preset, {}, {});
  let materialUse = base.material_use;
  let note = typeof raw.material_note === "string" ? raw.material_note : base.material_note;
  if (typeof raw.material_use === "string") {
    const parsed = parseMaterialUse(raw.material_use, base.material_use);
    if (parsed.ok) materialUse = parsed.use;
    else note = raw.material_use;
  } else if (raw.material_use && typeof raw.material_use === "object") {
    const m = raw.material_use as Record<string, unknown>;
    materialUse = Object.fromEntries(SOURCE_CLASSES.map((c) => [c, (MATERIAL_USES as readonly string[]).includes(String(m[c])) ? m[c] : base.material_use[c]])) as MaterialUse;
  }
  const more = (MORE_EVIDENCE as readonly string[]).includes(String(raw.more_evidence)) ? (raw.more_evidence as MoreEvidence) : base.more_evidence;
  return { ...base, ...raw, material_use: materialUse, material_note: note, more_evidence: more, sources: raw.sources ?? base.sources } as CasePolicy;
}

/**
 * A run's case policy as its kickoff recorded it; the default (standard,
 * network closed) for a run from before this module, or one whose record
 * does not read.
 */
export function readCasePolicy(sandbox: string): CasePolicy {
  try {
    const raw = JSON.parse(readFileSync(join(resolve(sandbox), POLICY_REL), "utf8")) as Partial<CasePolicy>;
    if (raw && (raw.v === 1 || raw.v === 2) && (PRESETS as readonly string[]).includes(String(raw.policy)) && (NETWORK_MODES as readonly string[]).includes(String(raw.network))) {
      return normalise(raw);
    }
  } catch {
    // no record: a run from before the case policy
  }
  return defaultPolicy();
}

/** Whether a run recorded its case policy (network/policy.json), and that record's sha256: what the custody anchor holds and custody checks. */
export function policyRecordSha(sandbox: string): string | null {
  try {
    return createHash("sha256").update(readFileSync(join(resolve(sandbox), POLICY_REL))).digest("hex");
  } catch {
    return null;
  }
}

/** The fields a resumed run's options may not change: every field of the policy but where each came from. */
export function policyDifferences(a: CasePolicy, b: CasePolicy): string[] {
  const out: string[] = [];
  const keys = ["policy", "network", "lookups", "contact", "disclosure", "evidence_link", "active_contact", "sockets", "category_override", "legal", "provider_retention", "more_evidence", "material_use"] as const;
  for (const k of keys) {
    const x = JSON.stringify((a as Record<string, unknown>)[k]);
    const y = JSON.stringify((b as Record<string, unknown>)[k]);
    if (x !== y) out.push(`${k}: recorded ${x}, these options ${y}`);
  }
  return out;
}

/** The policy in words, one line per field, for SWARM.md and the kickoff's output. */
export function policyLines(p: CasePolicy): string[] {
  const allowed = DISCLOSURE_CLASSES.filter((c) => p.disclosure[c] === "allow");
  return [
    `Case policy: ${p.policy}${p.sources.policy === "default" ? " (the default)" : ""}; network ${p.network}${p.sources.network === "legacy" ? " (--no-netguard)" : ""}.`,
    `Lookups the hub may grant by itself: ${p.lookups}; contact with what the evidence names: ${p.contact}${p.contact === "active" ? ` (${p.active_contact === "evidence_linked" ? "an evidence-linked adapter, granted by the hub" : p.active_contact === "operator" ? "each one the operator's" : "never"})` : " (active contact is the operator's)"}.`,
    `Case data that may leave the run: ${allowed.length ? allowed.join(", ") : "none"}; what a request sends must be in the evidence: ${p.evidence_link === "required" ? "always" : "for evidence-linked requests"}.`,
    `Socket grants (host and port only, no content capture): ${p.sockets === "operator" ? "the operator's to make" : "none"}; the operator may override a category denial: ${p.category_override ? "yes, with a reason" : "no"}.`,
    ...(p.legal ? [`Legal: ${p.legal}`] : []),
    ...(p.provider_retention ? [`Provider retention: ${p.provider_retention}`] : []),
    `More evidence during the run: ${p.more_evidence} (${MORE_EVIDENCE_WORDS[p.more_evidence]}).`,
    `Material from outside the original evidence, by class: ${SOURCE_CLASSES.map((c) => `${c} ${p.material_use[c]}`).join(", ")} (evidence: ${USE_WORDS.evidence}; reference: ${USE_WORDS.reference}; none: ${USE_WORDS.none}); ${p.material_note}.`,
  ];
}

// --- B16: what the goal names, against the policy and the catalogue ---------------------------------

/** A host's form as the goal may write it: a name with a public-looking suffix, or inside a URL. */
const URL_HOST = /\bhttps?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?/gi;
const BARE_HOST = /(?<![@\w/.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|org|net|io|gov|edu|info|dev|app|ai|co|uk|de|fr|nl|tr|ru|cn|jp|eu|us|ca|au|sh|me|tv|xyz|int|mil|be|ch|se|no|fi|dk|es|it|pl|br|in|kr|gl|ly|to))(?![\w-]|\.[a-z])/gi;

export type ServiceNote = { service: string; how: "adapter" | "denied" | "host"; adapter?: string; level: "ok" | "warn"; text: string };

/**
 * The services a goal names (hosts, in a URL or bare; an adapter's name or
 * host; a denied host's own name), each held to the case policy and the
 * adapter catalogue: whether this run can reach it, and how. Warnings only:
 * a goal may well name a service the run is not to use. The catalogue and the
 * deny list are passed in, and their absence is tolerated (nothing is said of
 * adapters then). Generic: names, hosts and the policy's rules, never words
 * about a case.
 */
export function goalServiceNotes(
  goalText: string,
  p: CasePolicy,
  lists: {
    adapters?: Array<{ name: string; title?: string; host: string; class: string; contact: string; disclosure: string; key?: { env: string } }>;
    deny?: { categories: Record<string, { why: string; hosts: string[] }> } | null;
    keys?: Set<string>;
  },
): ServiceNote[] {
  const text = goalText.replace(/^---[ \t]*\r?\n[\s\S]*?\r?\n---[ \t]*(?:\r?\n|$)/, "");
  const lower = text.toLowerCase();
  const adapters = (lists.adapters ?? []).filter((a) => a.host && a.host !== "from_url");
  const out: ServiceNote[] = [];
  const said = new Set<string>();
  const hostMatches = (host: string, entry: string): boolean => {
    const e = entry.toLowerCase();
    if (e.endsWith(".*")) {
      const label = e.slice(0, -2);
      return host === label || host.startsWith(`${label}.`) || host.includes(`.${label}.`);
    }
    return host === e || host.endsWith(`.${e}`);
  };
  const denyOf = (host: string): { category: string; why: string } | null => {
    for (const [category, c] of Object.entries(lists.deny?.categories ?? {})) if (c.hosts.some((h) => hostMatches(host, h))) return { category, why: c.why };
    return null;
  };
  const adapterWords = (a: (typeof adapters)[number]) => {
    const first = a.name.split("_")[0];
    const words = [a.host.toLowerCase()];
    if (first.length >= 4 && first !== "http") words.push(first);
    return words;
  };
  const allowedFor = (a: (typeof adapters)[number]): string | null => {
    if (p.network === "closed") return `this run's network is closed, so no lookup is made: run with --network dynamic for the catalogue's adapters, or the operator allows a host while the run goes on`;
    if (p.network === "open") return null;
    if (p.lookups === "none") return `policy ${p.policy} allows no lookup (lookups: none)`;
    if (a.class === "evidence_linked" && p.lookups === "reference") return `${a.name} is an evidence-linked lookup and this case allows reference lookups only`;
    if (a.contact === "active" && (p.contact === "passive" || p.active_contact !== "evidence_linked")) return `${a.name} contacts what the evidence names: ${p.active_contact === "never" ? `policy ${p.policy} never allows it` : "each such request is the operator's decision"}`;
    if (a.disclosure !== "none" && (DISCLOSURE_CLASSES as readonly string[]).includes(a.disclosure) && p.disclosure[a.disclosure as DisclosureClass] !== "allow") return `${a.name} sends ${a.disclosure} out of the run, which policy ${p.policy} does not allow`;
    if (a.key && !(lists.keys ?? new Set()).has(a.key.env)) return `${a.name} needs a host-managed key (${a.key.env}) that is not configured on this host`;
    return null;
  };
  for (const a of adapters) {
    const hit = adapterWords(a).find((w) => new RegExp(`(?<![\\w.-])${w.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w-]|\\.[a-z])`, "i").test(lower));
    if (!hit || said.has(a.host)) continue;
    said.add(a.host);
    const why = allowedFor(a);
    out.push(why ? { service: hit, how: "adapter", adapter: a.name, level: "warn", text: `the goal names ${hit} (adapter ${a.name}), and ${why}` } : { service: hit, how: "adapter", adapter: a.name, level: "ok", text: `the goal names ${hit}: adapter ${a.name} reaches it under policy ${p.policy}, network ${p.network}` });
  }
  const hosts = new Set<string>();
  for (const m of text.matchAll(URL_HOST)) hosts.add(m[1].toLowerCase());
  for (const m of text.matchAll(BARE_HOST)) hosts.add(m[1].toLowerCase());
  for (const host of hosts) {
    if (said.has(host) || adapters.some((a) => hostMatches(host, a.host))) continue;
    said.add(host);
    const d = denyOf(host);
    if (d) {
      out.push({ service: host, how: "denied", level: "warn", text: `the goal names ${host}, which the case policy's hard denials refuse (${d.category}: ${d.why}): the swarm cannot use it${p.category_override && d.category !== "login" && d.category !== "upload" && d.category !== "credential" ? ", unless the operator overrides it with a reason" : ""}` });
      continue;
    }
    out.push({
      service: host,
      how: "host",
      level: p.network === "open" ? "ok" : "warn",
      text:
        p.network === "open"
          ? `the goal names ${host}: the network is open, so it is reached directly, neither mediated nor captured`
          : p.network === "closed"
            ? `the goal names ${host}, which this run's closed network does not reach: allow it at kickoff (--allow-host, a socket allowance) or while the run goes on (swarm.sh lead note --allow-host), where the case policy permits it`
            : `the goal names ${host}, which no adapter of the catalogue reaches: a request for it is refused as uncertain, and only the operator can grant it`,
    });
  }
  // A denied service named by its own name ("search Google for"): the deny list's labels.
  for (const [category, c] of Object.entries(lists.deny?.categories ?? {})) {
    for (const h of c.hosts) {
      const label = h.replace(/\.\*$/, "").split(".")[0];
      if (label.length < 4 || said.has(label)) continue;
      if (!new RegExp(`(?<![\\w.-])${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w-])`, "i").test(lower)) continue;
      if ([...said].some((s) => s.startsWith(`${label}.`) || s.includes(`.${label}.`))) continue;
      said.add(label);
      out.push({ service: label, how: "denied", level: "warn", text: `the goal names ${label}, a service the case policy's hard denials refuse (${category}: ${c.why}): the swarm cannot use it` });
    }
  }
  return out;
}

async function main(argv: string[]): Promise<void> {
  const cmd = argv[0];
  const opt = (name: string) => {
    const i = argv.indexOf(name);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  if (cmd === "resolve") {
    const goalFile = opt("--goal-file");
    const goal = goalFile && existsSync(goalFile) ? goalPolicyKeys(readFileSync(goalFile, "utf8")) : {};
    const flags: Record<string, string> = {};
    for (const k of POLICY_KEYS) {
      const v = opt(POLICY_FLAGS[k]);
      if (v !== undefined && v !== "") flags[k] = v;
    }
    const iso = opt("--isolation");
    const r = resolveCasePolicy({
      goal,
      flags,
      legacyOpen: argv.includes("--legacy-open"),
      ...(iso === "host" || iso === "microvm" ? { isolation: iso } : {}),
      allowHosts: (opt("--allow-hosts") ?? "").split(",").filter(Boolean),
    });
    process.stdout.write(`${JSON.stringify(r.ok ? { ...r, lines: policyLines(r.policy) } : r)}\n`);
    process.exit(r.ok ? 0 : 1);
  }
  if (cmd === "check-egress") {
    const raw = opt("--policy-json");
    if (!raw) throw new Error("check-egress needs --policy-json");
    const split = (v?: string) => (v ?? "").split(",").filter(Boolean);
    const parsed = JSON.parse(raw) as CasePolicy | null;
    const conflicts = !parsed ? [] : egressConflicts(parsed, { allowHosts: split(opt("--allow-hosts")), installHosts: split(opt("--install-hosts")), packHosts: split(opt("--pack-hosts")) });
    process.stdout.write(`${JSON.stringify({ ok: !conflicts.length, conflicts })}\n`);
    process.exit(conflicts.length ? 1 : 0);
  }
  if (cmd === "check-spec") {
    const raw = opt("--policy-json");
    const specFile = opt("--spec");
    const jobsRaw = opt("--jobs-json");
    const parsed = raw ? (JSON.parse(raw) as CasePolicy | null) : null;
    const spec = specFile && existsSync(specFile) ? (JSON.parse(readFileSync(specFile, "utf8")) as { open_net?: unknown }) : null;
    const jobs = jobsRaw ? (JSON.parse(jobsRaw) as { openNet?: unknown }) : null;
    const conflicts = specConflicts(parsed ? normalise(parsed) : null, spec, jobs);
    process.stdout.write(`${JSON.stringify({ ok: !conflicts.length, conflicts })}\n`);
    process.exit(conflicts.length ? 1 : 0);
  }
  if (cmd === "services") {
    const goalFile = opt("--goal-file");
    const raw = opt("--policy-json");
    if (!goalFile || !raw) throw new Error("services needs --goal-file and --policy-json");
    const p = normalise(JSON.parse(raw) as CasePolicy);
    const text = existsSync(goalFile) ? readFileSync(goalFile, "utf8") : "";
    // The catalogue and the deny list are WP6's: tolerated when absent.
    let adapters: Parameters<typeof goalServiceNotes>[2]["adapters"] = [];
    let deny: Parameters<typeof goalServiceNotes>[2]["deny"] = null;
    try {
      const A = await import("./net-adapters.ts");
      adapters = A.loadCatalogue().adapters;
      deny = A.loadDeny();
    } catch {
      // no catalogue: the hosts alone are said
    }
    const keys = new Set(Object.keys(process.env).filter((k) => /^DFIRSWARM_[A-Z0-9_]+_API_KEY$/.test(k) && process.env[k]));
    process.stdout.write(`${JSON.stringify({ notes: goalServiceNotes(text, p, { adapters, deny, keys }) })}\n`);
    return;
  }
  if (cmd === "show") {
    const S = argv[1];
    if (!S) throw new Error("show needs the run's sandbox");
    const p = readCasePolicy(S);
    process.stdout.write(`${JSON.stringify({ policy: p, lines: policyLines(p), sha256: policyRecordSha(S) })}\n`);
    return;
  }
  if (cmd === "compare") {
    const S = argv[1];
    const raw = opt("--policy-json");
    if (!S || !raw) throw new Error("compare needs the run's sandbox and --policy-json");
    const recorded = existsSync(join(resolve(S), POLICY_REL)) ? readCasePolicy(S) : null;
    const now = normalise(JSON.parse(raw) as CasePolicy);
    process.stdout.write(`${JSON.stringify({ recorded, differences: recorded ? policyDifferences(recorded, now) : [] })}\n`);
    return;
  }
  process.stderr.write("case-policy: usage: case-policy.ts resolve [--goal-file F] [--policy P] [--network M] [--lookups L] [--contact C] [--disclosure LIST] [--more-evidence no|ask|yes] [--material-use SPEC] [--legal TEXT] [--provider-retention TEXT] [--legacy-open] [--isolation I] [--allow-hosts LIST] | check-egress | services --goal-file F --policy-json JSON | show <sandbox> | compare <sandbox> --policy-json JSON\n");
  process.exit(2);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`case-policy: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
