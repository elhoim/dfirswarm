#!/usr/bin/env node
/**
 * The case policy: what an examination permits to leave the run and to
 * reach outside it, set once at kickoff and recorded with the run.
 *
 * Two controls, kept apart (docs/adr/0011). The run's **network mode** says
 * how access is decided: `closed` (today's default: the models' hosts, the
 * package index when installs are allowed, and the operator's own hosts),
 * `dynamic` (an agent asks, the hub decides under this policy, a host-side
 * fetch service carries it out) or `open` (every public host, as
 * `--no-netguard` has always meant). The **case policy** says what the
 * examination permits whatever the mode: which lookups, whether the subject's
 * infrastructure may be contacted, which classes of case data may leave, the
 * legal text the operator fills in. An agent can weaken neither: both are
 * the kickoff's, recorded in `network/policy.json`, SWARM.md and the run's
 * registry record, and read on every decision.
 *
 * A preset sets every field; the goal's metadata block and the kickoff's
 * flags override single fields; a combination that contradicts its preset is
 * refused at kickoff, never resolved by guessing. A run that says nothing is
 * `standard` with the network `closed`, which is what every run was before
 * this module: nothing changes for it.
 *
 * WP3 of Plan 3 owns the whole case contract (acquisition, material use);
 * this module is its seed and holds the fields WP3 defines, so the network
 * part can be enforced now and the rest recorded.
 *
 *   node --experimental-strip-types scripts/case-policy.ts resolve [--goal-file F]
 *        [--policy P] [--network M] [--lookups L] [--contact C] [--disclosure LIST]
 *        [--legacy-open] [--isolation microvm|host] [--allow-hosts LIST]
 *   node --experimental-strip-types scripts/case-policy.ts show <sandbox>
 */
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
export const MORE_EVIDENCE = ["no", "ask", "yes"] as const;
export type MoreEvidence = (typeof MORE_EVIDENCE)[number];

/** Where a field's value came from. */
export type Source = "preset" | "goal" | "flag" | "legacy" | "default";

export type CasePolicy = {
  v: 1;
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
  /** Whether more evidence may arrive during the run (WP3's acquisition lane). */
  more_evidence: MoreEvidence;
  /** What supplied and captured material may be used for (WP3). */
  material_use: string;
  sources: Record<string, Source>;
};

type PresetBody = Omit<CasePolicy, "v" | "policy" | "network" | "sources" | "legal" | "provider_retention" | "material_use"> & { network?: NetworkMode; material_use: string };

const allow = (...classes: DisclosureClass[]): Record<DisclosureClass, "allow" | "deny"> =>
  Object.fromEntries(DISCLOSURE_CLASSES.map((c) => [c, classes.includes(c) ? "allow" : "deny"])) as Record<DisclosureClass, "allow" | "deny">;

/**
 * The four presets (the owner's decision of 2026-09-28: `standard` by
 * default). `standard`: only hashes and public indicators, to approved
 * passive adapters; active contact is the operator's. `live_adversary`:
 * stricter, no contact with anything the evidence names, at all.
 * `internal`: nothing leaves. `ctf`: a published case, where write-ups
 * exist: no search, no write-up site, only reference or evidence-linked
 * adapters, and whatever is sent must be in the evidence.
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
    material_use: "reference: an examiner records what a capture or supplied material establishes",
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
    material_use: "reference: an examiner records what a capture or supplied material establishes",
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
    material_use: "internal: nothing leaves the run",
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
    material_use: "reference: an examiner records what a capture establishes; a published case's write-ups are never material",
  },
};

/** The policy of a run that says nothing: standard, with the network closed. */
export function defaultPolicy(): CasePolicy {
  return build("standard", {}, {});
}

function build(preset: Preset, overrides: Partial<Record<string, string>>, from: Record<string, Source>): CasePolicy {
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
  return {
    v: 1,
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
    material_use: pick<string>("material_use", p.material_use),
    sources,
  };
}

/** The keys the goal's metadata block and the kickoff may set. */
export const POLICY_KEYS = ["policy", "network", "lookups", "contact", "disclosure", "legal", "provider_retention", "more_evidence", "material_use"] as const;

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

/**
 * The run's case policy from its flags, its goal and its preset, or the
 * conflicts that stop the kickoff. Each value is checked against its
 * vocabulary, and the combination against its preset: an internal case
 * cannot look anything up, a published case cannot be open, and so on.
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
  const lower = (k: string) => {
    if (merged[k] !== undefined && !["legal", "provider_retention", "material_use", "disclosure"].includes(k)) merged[k] = merged[k].toLowerCase();
  };
  for (const k of POLICY_KEYS) lower(k);
  const check = (k: string, vocab: readonly string[]) => {
    if (merged[k] !== undefined && !vocab.includes(merged[k])) conflicts.push(`${k}: ${JSON.stringify(merged[k])} is not one of ${vocab.join(", ")} (${from[k] === "goal" ? "the goal's metadata block" : "the kickoff's flag"})`);
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
  const overrides: Record<string, string> = { ...merged };
  delete overrides.policy;
  const policy = build(preset, overrides, from);
  // The combination, against its preset.
  const allowed = DISCLOSURE_CLASSES.filter((c) => policy.disclosure[c] === "allow");
  if (preset === "internal") {
    if (policy.network === "open") conflicts.push("policy internal: nothing leaves the run, which contradicts network: open");
    if (policy.lookups !== "none") conflicts.push(`policy internal: nothing leaves the run, which contradicts lookups: ${policy.lookups}`);
    if (policy.contact !== "passive") conflicts.push("policy internal: nothing leaves the run, which contradicts contact: active");
    if (allowed.length) conflicts.push(`policy internal: nothing leaves the run, which contradicts disclosure: ${allowed.join(",")}`);
  }
  if (preset === "ctf") {
    if (policy.network === "open") conflicts.push("policy ctf: every lookup of a published case goes through the fetch service (network: dynamic or closed), which contradicts network: open");
    if (policy.lookups === "any") conflicts.push("policy ctf: only reference or evidence-linked lookups, which contradicts lookups: any");
    for (const c of ["internal_name", "personal", "file_upload"] as const) if (policy.disclosure[c] === "allow") conflicts.push(`policy ctf: disclosure ${c} is not a published case's`);
  }
  if (preset === "live_adversary") {
    if (policy.contact === "active") conflicts.push("policy live_adversary: nothing the evidence names is contacted, which contradicts contact: active");
    if (policy.network === "open") conflicts.push("policy live_adversary: every lookup is mediated, which contradicts network: open");
  }
  if (policy.disclosure.file_upload === "allow") notes.push("disclosure file_upload is recorded, but no adapter uploads: an upload stays refused by the hard denials");
  if (policy.lookups === "none" && policy.contact === "active") notes.push("contact: active with lookups: none grants nothing: no lookup is allowed");
  if (policy.network === "dynamic" && input.isolation === "host") conflicts.push("network: dynamic needs the hub and the fetch service of a microVM run; a host run's network is closed or open (--no-netguard)");
  const hosts = (input.allowHosts ?? []).filter(Boolean);
  if (hosts.length && policy.sockets === "none") conflicts.push(`policy ${preset}: --allow-host ${hosts.join(",")} would be a socket allowance (host and port, no method or path control, no content capture), which this case policy does not permit; ${preset === "ctf" ? "a published case's lookups go through the fetch service (network: dynamic)" : "drop the host"}`);
  if (conflicts.length) return { ok: false, conflicts, notes };
  return { ok: true, policy, notes };
}

/** Where a run's case policy is recorded, and read on every network decision. */
export const POLICY_REL = "network/policy.json";

/**
 * A run's case policy as its kickoff recorded it; the default (standard,
 * network closed) for a run from before this module, or one whose record
 * does not read.
 */
export function readCasePolicy(sandbox: string): CasePolicy {
  try {
    const raw = JSON.parse(readFileSync(join(resolve(sandbox), POLICY_REL), "utf8")) as Partial<CasePolicy>;
    if (raw && raw.v === 1 && (PRESETS as readonly string[]).includes(String(raw.policy)) && (NETWORK_MODES as readonly string[]).includes(String(raw.network))) {
      return { ...defaultPolicy(), ...raw } as CasePolicy;
    }
  } catch {
    // no record: a run from before the case policy
  }
  return defaultPolicy();
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
    `More evidence during the run: ${p.more_evidence}; material use: ${p.material_use}.`,
  ];
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
    for (const k of ["policy", "network", "lookups", "contact", "disclosure"]) {
      const v = opt(`--${k}`);
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
  if (cmd === "show") {
    const S = argv[1];
    if (!S) throw new Error("show needs the run's sandbox");
    const p = readCasePolicy(S);
    process.stdout.write(`${JSON.stringify({ policy: p, lines: policyLines(p) })}\n`);
    return;
  }
  process.stderr.write("case-policy: usage: case-policy.ts resolve [--goal-file F] [--policy P] [--network M] [--lookups L] [--contact C] [--disclosure LIST] [--legacy-open] [--isolation I] [--allow-hosts LIST] | show <sandbox>\n");
  process.exit(2);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    process.stderr.write(`case-policy: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
