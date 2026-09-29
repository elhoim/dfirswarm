import type { ArtifactIndex, Coverage, Dossier, ImagePreview, Job, OperatorAudit, PackageInfo, StartCheck, PackRow, EntryReviewAction, ReviewState, ExaminersView, EnrolledPerson, ReleaseStateView, PreparedRelease, VmReadiness, ModelList, SwarmRow, SwarmView, TimedPost, TracePage, WorkFile, FileVersion, Health, GoalSummary, StoreJobDetail, StoreJobsView, StoreLogPage,
  LibraryDocument,
  LibraryEntry, GoalDocument, SwarmContract, ChecksReport, ReadinessReport, ForgedToolSource, InputsLibrary, LeadsPanelView, QuestionsPanelView, NetworkPanelView, RequestsPanelView } from "./types";

/**
 * The token that lets this browser start, stop, reap and restore. The server
 * prints it in the URL it hosts; we keep it so a reload does not lose it.
 * Watching never needs one.
 */
const TOKEN_KEY = "swarm.ui.token";

function readTokenFromUrl(): string | null {
  try {
    const url = new URL(window.location.href);
    // Preferred: the fragment, which browsers never send to the server.
    const hash = new URLSearchParams(url.hash.replace(/^#/, ""));
    const fromHash = hash.get("token");
    if (fromHash) {
      hash.delete("token");
      const rest = hash.toString();
      url.hash = rest ? `#${rest}` : "";
      window.history.replaceState({}, "", url.toString());
      return fromHash;
    }
    return null;
  } catch {
    return null;
  }
}

let token: string | null = null;
try {
  token = readTokenFromUrl();
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else token = localStorage.getItem(TOKEN_KEY);
} catch {
  // private mode or no storage: the token simply does not persist
}

export function setToken(value: string): void {
  token = value.trim() || null;
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    // nothing to do; the token lives for this page only
  }
}

export class ApiError extends Error {
  status: number;
  body: unknown;
  constructor(status: number, message: string, body?: unknown) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, { ...init, headers: { accept: "application/json", ...(init?.headers ?? {}) } });
  } catch (err) {
    // A dead server is a TypeError whose message is "Failed to fetch" — which
    // reads, in a panel, as though the panel were broken. It is the console
    // that is gone: the page still holds the data it loaded before, so only
    // the newest request fails and the rest of the screen looks fine.
    throw new ApiError(0, `The console server did not answer. It is probably no longer running — restart it with scripts/swarm.sh ui, then reload. (${err instanceof Error ? err.message : String(err)})`);
  }
  const text = await res.text();
  let body: unknown = text;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    // leave as text
  }
  if (!res.ok) {
    const message =
      typeof body === "object" && body !== null && "error" in body
        ? String((body as { error: unknown }).error)
        : typeof body === "object" && body !== null && "reason" in body
          ? String((body as { reason: unknown }).reason)
          : `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, message, body);
  }
  return body as T;
}

function sendOnce<T>(method: string, path: string, payload: unknown): Promise<T> {
  return request<T>(path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
  });
}

/**
 * Every mutating call goes through here, so a rotated or missing token is
 * recoverable from wherever the operator happens to be — stop and reap used
 * to fail with a bare 401 because only the kickoff form asked for one.
 */
async function sendJson<T>(method: string, path: string, payload: unknown): Promise<T> {
  try {
    return await sendOnce<T>(method, path, payload);
  } catch (err) {
    if (!(err instanceof ApiError) || err.status !== 401 || typeof window === "undefined") throw err;
    const entered = window.prompt(
      "This server needs its token for start / stop / reap / restore / saving a goal.\nPaste the token from the URL the server printed:",
    );
    if (!entered) throw err;
    setToken(entered);
    return sendOnce<T>(method, path, payload);
  }
}

function postJson<T>(path: string, payload: unknown): Promise<T> {
  return sendJson<T>("POST", path, payload);
}

export const api = {
  health: () => request<Health>("/api/health"),
  swarms: () => request<SwarmRow[]>("/api/swarms"),
  swarm: (id: string) => request<SwarmView>(`/api/swarms/${encodeURIComponent(id)}`),
  thread: (id: string, thread: string) => request<TimedPost[]>(`/api/swarms/${encodeURIComponent(id)}/threads/${encodeURIComponent(thread)}`),
  /** Every post across every thread, bodies included — what the board analytics reads. */
  posts: (id: string) => request<TimedPost[]>(`/api/swarms/${encodeURIComponent(id)}/posts`),
  traces: (id: string, q: { agent?: string; tool?: string; q?: string; limit?: number; order?: "asc" | "desc"; spilled?: boolean }) => {
    const params = new URLSearchParams();
    if (q.spilled) params.set("spilled", "1");
    if (q.agent) params.set("agent", q.agent);
    if (q.tool) params.set("tool", q.tool);
    if (q.q) params.set("q", q.q);
    if (q.limit) params.set("limit", String(q.limit));
    if (q.order) params.set("order", q.order);
    return request<TracePage>(`/api/swarms/${encodeURIComponent(id)}/traces?${params}`);
  },
  work: (id: string) => request<WorkFile[]>(`/api/swarms/${encodeURIComponent(id)}/work`),
  artifacts: (id: string) => request<ArtifactIndex>(`/api/swarms/${encodeURIComponent(id)}/artifacts`),
  /** The handover as one product: report HTML, artifact index, files with hashes. */
  dossier: (id: string) => request<Dossier>(`/api/swarms/${encodeURIComponent(id)}/dossier`),
  /** A dossier file, as a download with a filename and the run's id on it. */
  dossierUrl: (id: string, name: string) => `/api/swarms/${encodeURIComponent(id)}/dossier/${encodeURIComponent(name)}`,
  workUrl: (id: string, path: string) => `/api/swarms/${encodeURIComponent(id)}/${path.split("/").map(encodeURIComponent).join("/")}`,
  /**
   * A one-time grant to open one HTML artifact with its scripts: the server
   * binds it to the path and the file's sha256, spends it on first use and
   * lets it lapse in a minute. Needs the token.
   */
  workScriptsGrant: (id: string, path: string) =>
    postJson<{ grant: string; path: string; sha256: string; expires_in_ms: number }>(`/api/swarms/${encodeURIComponent(id)}/work-scripts`, { path }),
  history: (id: string) => request<Record<string, FileVersion[]>>(`/api/swarms/${encodeURIComponent(id)}/history`),
  revision: (id: string, path: string, rev: number) =>
    request<{ path: string; rev: number; text: string; versions: FileVersion[] }>(
      `/api/swarms/${encodeURIComponent(id)}/history/rev?path=${encodeURIComponent(path)}&rev=${rev}`,
    ),
  restore: (id: string, path: string, rev: number) =>
    postJson<{ ok: boolean; path: string; rev: number; reason?: string }>(`/api/swarms/${encodeURIComponent(id)}/history/restore`, { path, rev }),
  models: () => request<ModelList>("/api/models"),
  readiness: () => request<ReadinessReport>("/api/models/readiness"),
  contract: (id: string) => request<SwarmContract>(`/api/swarms/${encodeURIComponent(id)}/contract`),
  tool: (id: string, name: string) => request<ForgedToolSource>(`/api/swarms/${encodeURIComponent(id)}/tools/${encodeURIComponent(name)}`),
  checks: (id: string) => request<ChecksReport>(`/api/swarms/${encodeURIComponent(id)}/checks`),
  goals: () => request<{ goals: GoalSummary[] }>("/api/goals"),
  library: () => request<{ entries: LibraryEntry[] }>("/api/library"),
  /** Packs installed with pack.sh; the kickoff's pack field. */
  packs: () => request<{ packs: PackRow[] }>("/api/packs"),
  /** Can this host run the agents in microVMs (msb, doctor, the image, capacity), asked before Start. */
  vmImage: (q: { packs: string[]; playwright: boolean; tools_from?: string }) => {
    const params = new URLSearchParams({ packs: q.packs.join(","), playwright: q.playwright ? "1" : "0" });
    if (q.tools_from) params.set("tools_from", q.tools_from);
    return request<ImagePreview>(`/api/vm/image?${params}`);
  },
  vmReadiness: (q: { image?: string; n?: number; cpus?: number; memory?: number }) => {
    const params = new URLSearchParams();
    if (q.image) params.set("image", q.image);
    if (q.n) params.set("n", String(q.n));
    if (q.cpus) params.set("cpus", String(q.cpus));
    if (q.memory) params.set("memory", String(q.memory));
    return request<VmReadiness>(`/api/vm/readiness?${params}`);
  },
  /** The start flags this harness documents (swarm.sh help start). */
  kickoffFlags: () => request<{ flags: string[] }>("/api/kickoff/flags"),
  operator: (id: string) => request<OperatorAudit>(`/api/swarms/${encodeURIComponent(id)}/operator`),
  /** The lead register: every lead, the operator's queue first, and the questions nobody covers. */
  leads: (id: string) => request<LeadsPanelView>(`/api/swarms/${encodeURIComponent(id)}/leads`),
  /** The operator's answer to a lead (note, with a host to allow for the run's jobs), or a reopen: run as swarm.sh lead. Needs the token. */
  leadAct: (id: string, payload: { action: "note" | "reopen"; lead: string; text?: string; allow_host?: string }) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/leads`, payload),
  /** A directive: an unheld lead under a question (or under one asked with it), with its product and acceptance; run as swarm.sh lead direct. Needs the token. */
  leadDirect: (id: string, payload: { q?: string; new_question?: string; new_why?: string; title: string; why: string; product: string; acceptance: string; as?: string }) =>
    postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/leads`, { action: "direct", ...payload }),
  /** The question register: every question, who asked it, its scope, work and answer; the triage and the clarifications. */
  questions: (id: string) => request<QuestionsPanelView>(`/api/swarms/${encodeURIComponent(id)}/questions`),
  /** An act on the question register (add, amend, priority, scope, withdraw, clarify_reply, accept), run as swarm.sh question. Needs the token. */
  questionAct: (id: string, payload: Record<string, unknown> & { action: string }) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/questions`, payload),
  /** The dynamic network: the case policy, what waits on the operator, requests, grants and captures. */
  network: (id: string) => request<NetworkPanelView>(`/api/swarms/${encodeURIComponent(id)}/network`),
  /** The operator's act on the network, with its reason: run as swarm.sh net. Needs the token. */
  netAct: (id: string, payload: { action: "grant" | "deny" | "revoke" | "socket"; target?: string; why: string; host?: string; lead?: string }) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/network`, payload),
  /** The operator requests: everything the run asked of a person, with its id and how it stands; the evidence and material added. */
  requests: (id: string) => request<RequestsPanelView>(`/api/swarms/${encodeURIComponent(id)}/requests`),
  /** An act on an operator request (ack, answer, decline, withdraw, an acquisition's stage), run as swarm.sh requests. Needs the token. */
  requestAct: (id: string, payload: { action: "ack" | "answer" | "decline" | "withdraw" | "authorise" | "collecting" | "unavailable"; request: string; text?: string; why?: string; as?: string }) =>
    postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/requests`, payload),
  /** The run's tool jobs from the job service's journal: a page, with the totals over all of them. */
  storeJobs: (id: string, q: { offset: number; limit: number }) =>
    request<StoreJobsView>(`/api/swarms/${encodeURIComponent(id)}/jobs?offset=${q.offset}&limit=${q.limit}`),
  /** One tool job: its record, its journal lines, a page of one sealed tree's manifest, its logs. */
  storeJob: (id: string, job: string, q: { tree?: string; offset: number; limit: number }) =>
    request<StoreJobDetail>(`/api/swarms/${encodeURIComponent(id)}/jobs/${encodeURIComponent(job)}?${new URLSearchParams({ ...(q.tree ? { tree: q.tree } : {}), offset: String(q.offset), limit: String(q.limit) })}`),
  storeJobLog: (id: string, job: string, name: string, q: { offset: number; limit: number }) =>
    request<StoreLogPage>(`/api/swarms/${encodeURIComponent(id)}/jobs/${encodeURIComponent(job)}/log/${encodeURIComponent(name)}?offset=${q.offset}&limit=${q.limit}`),
  /** A job's log whole, as plain text; `download` saves it. */
  storeJobLogUrl: (id: string, job: string, name: string, download = false) =>
    `/api/swarms/${encodeURIComponent(id)}/jobs/${encodeURIComponent(job)}/log/${encodeURIComponent(name)}?raw=1${download ? "&download=1" : ""}`,
  coverage: (id: string) => request<Coverage>(`/api/swarms/${encodeURIComponent(id)}/coverage`),
  review: (id: string) => request<ReviewState>(`/api/swarms/${encodeURIComponent(id)}/review`),
  /** One examiner decision on an entry; written by swarm.sh review. Needs the token. The sign-off is the Release panel's. */
  sendReview: (id: string, payload: { action: EntryReviewAction; entry_seq?: number; note?: string; examiner: string }) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/review`, payload),
  /** Who is enrolled on this install, and whether this console can sign. */
  examiners: () => request<ExaminersView>("/api/examiners"),
  /** Enrol an examiner or a reviewer: an ssh key made with a passphrase, a FIDO key (a touch), or a token's certificate. */
  enroll: (payload: Record<string, unknown>) => postJson<{ ok: boolean; person: EnrolledPerson; register: string | null }>("/api/examiners/enroll", payload),
  releaseState: (id: string) => request<ReleaseStateView>(`/api/runs/${encodeURIComponent(id)}/release`),
  /** The first half of an adoption: the final bytes rendered once, and what will be signed. */
  prepareRelease: (id: string, payload: { examiner: string; pdf?: boolean; amend_reason?: string }) => postJson<PreparedRelease>(`/api/runs/${encodeURIComponent(id)}/release/prepare`, payload),
  /** The second half: the secret goes to the server once, over loopback, and down a pipe to the signing script. */
  sealRelease: (id: string, payload: { nonce: string; shown_sha256: string; examiner: string; secret: string; consent: true }) => postJson<{ ok: boolean; version: number; sha256: string; line: string }>(`/api/runs/${encodeURIComponent(id)}/release/seal`, payload),
  discardRelease: (id: string, nonce: string) => postJson<{ ok: boolean }>(`/api/runs/${encodeURIComponent(id)}/release/discard`, { nonce }),
  technicalReview: (id: string, payload: { reviewer: string; outcome: string; checked: string; entries?: number[]; all_answers?: boolean; disagreements?: string[]; reviewed_at?: string; secret: string; consent: true }) =>
    postJson<{ ok: boolean; seq: number; countersign_seq: number }>(`/api/runs/${encodeURIComponent(id)}/review/technical`, payload),
  countersign: (id: string, payload: { reviewer: string; seq: number; secret: string; consent: true }) => postJson<{ ok: boolean; seq: number }>(`/api/runs/${encodeURIComponent(id)}/review/countersign`, payload),
  hold: (id: string, reason: string) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/hold`, { reason }),
  release: (id: string) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/release`, {}),
  exportLedger: (id: string, format: "csv" | "timesketch") => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/export`, { format }),
  exportUrl: (jobId: string) => `/api/jobs/${encodeURIComponent(jobId)}/download`,
  packageRun: (id: string, sign: boolean) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/package`, { sign }),
  /** What swarm.sh package left in the run's sandbox. */
  packageInfo: (id: string) => request<PackageInfo>(`/api/swarms/${encodeURIComponent(id)}/package`),
  /** The package directory as one zip; swarm.sh verify takes it as it takes the directory. */
  packageZipUrl: (id: string) => `/api/swarms/${encodeURIComponent(id)}/package.zip`,
  verifyPackage: (id: string, pkg: string) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/verify`, { package: pkg }),
  purge: (id: string, confirm: string) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/purge`, { confirm }),
  libraryEntry: (id: string) => request<LibraryDocument>(`/api/library/${id.split("/").map(encodeURIComponent).join("/")}`),
  inputs: () => request<InputsLibrary>("/api/inputs"),
  /** Only when the server was started with --allow-inputs-root-from-ui; otherwise a 403 with the command to use. */
  addInputsRoot: (path: string) => postJson<InputsLibrary>("/api/inputs/roots", { path }),
  removeInputsRoot: (index: number) => sendJson<InputsLibrary>("DELETE", `/api/inputs/roots/${index}`, undefined),
  goal: (name: string) => request<GoalDocument>(`/api/goals/${encodeURIComponent(name)}`),
  saveGoal: (name: string, text: string) =>
    sendJson<GoalDocument>("PUT", `/api/goals/${encodeURIComponent(name)}`, { text }),
  deleteGoal: (name: string) =>
    sendJson<{ ok: boolean; name: string }>("DELETE", `/api/goals/${encodeURIComponent(name)}`, undefined),
  jobs: () => request<Job[]>("/api/jobs"),
  job: (id: string) => request<Job>(`/api/jobs/${encodeURIComponent(id)}`),
  start: (payload: Record<string, unknown>) => postJson<Job>("/api/swarms", payload),
  /** `swarm.sh start --check` with the same payload: the start's own checks, nothing written. */
  checkStart: (payload: Record<string, unknown>) => postJson<StartCheck>("/api/start/check", payload),
  stop: (id: string, opts: { no_custody?: boolean; custody_timeout?: number } = {}) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/stop`, opts),
  reap: (id: string, payload: { stall_sec?: number; stop?: boolean }) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/reap`, payload),
  /** More room for a going or paused run: swarm.sh extend. */
  extend: (id: string, payload: { minutes?: number; tokens?: number; usd?: number }) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/extend`, payload),
  /** Lift a pause whose cause is gone: swarm.sh unpause. */
  unpause: (id: string) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/unpause`, {}),
  /** "Continue this run": swarm.sh resume, with the questions asked for the continuation. */
  resume: (id: string, payload: { questions?: string[]; why?: string; minutes?: number; tokens?: number; usd?: number; as?: string }) => postJson<Job>(`/api/swarms/${encodeURIComponent(id)}/resume`, payload),
  /** A job's whole output, as plain text. */
  jobOutputUrl: (id: string, stream: "stdout" | "stderr") => `/api/jobs/${encodeURIComponent(id)}/output?stream=${stream}`,
};
