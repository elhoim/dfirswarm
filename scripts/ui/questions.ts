/**
 * The console's side of the question register: a request from the Questions
 * tab (or the Leads tab's "Add directive") turned into the `swarm.sh
 * question` or `swarm.sh lead … direct` command line the operator would type.
 * The server checks the shape (which act, which fields, how long); the CLI
 * does the real checking, writes the chain, and says what it did. The
 * console session's chosen person travels as `--as ID`: a claim, as it is on
 * the command line; signing a question act is the command line's.
 */

export class QuestionRequestError extends Error {
  constructor(message: string) {
    super(message);
  }
}

const Q_ID = /^Q-[1-9]\d{0,5}$/;
const L_ID = /^L-[1-9]\d{0,5}$/;
const C_ID = /^C-[1-9]\d{0,5}$/;
const PERSON = /^[a-z0-9][a-z0-9-]{0,47}$/;

function text(body: Record<string, unknown>, key: string, max: number, required = false): string {
  const v = body[key];
  if (v === undefined || v === null || v === "") {
    if (required) throw new QuestionRequestError(`${key} is required`);
    return "";
  }
  if (typeof v !== "string") throw new QuestionRequestError(`${key} is text`);
  const t = v.trim();
  if (required && !t) throw new QuestionRequestError(`${key} is required`);
  if (t.length > max) throw new QuestionRequestError(`${key} is over ${max} characters: nothing is cut, so a longer one is refused`);
  return t;
}

function id(body: Record<string, unknown>, key: string, re: RegExp, what: string): string {
  const v = String(body[key] ?? "").trim().toUpperCase();
  if (!re.test(v)) throw new QuestionRequestError(`${key} is ${what}`);
  return v;
}

function opt(argv: string[], flag: string, value: string): void {
  if (value) argv.push(flag, value);
}

/** The acting person the console session chose (a claim), as --as. */
function person(body: Record<string, unknown>): string[] {
  const as = typeof body.as === "string" ? body.as.trim() : "";
  if (!as) return [];
  if (!PERSON.test(as)) throw new QuestionRequestError("as is an enrolled person's id");
  return ["--as", as];
}

export const QUESTION_ACTIONS = ["add", "amend", "priority", "scope", "withdraw", "clarify_reply", "accept"] as const;

/** A Questions tab request as `swarm.sh question <id> <sub> …` arguments. */
export function questionArgv(body: Record<string, unknown>): { sub: string; argv: string[] } {
  const action = String(body.action ?? "");
  if (!(QUESTION_ACTIONS as readonly string[]).includes(action)) throw new QuestionRequestError(`action is one of ${QUESTION_ACTIONS.join(", ")}`);
  const argv: string[] = [];
  switch (action) {
    case "add": {
      argv.push("--text", text(body, "text", 4000, true), "--why", text(body, "why", 2000, true));
      const objective = text(body, "objective", 32);
      if (objective && objective !== "new" && !/^[A-Za-z][A-Za-z0-9._-]{0,31}$/.test(objective)) throw new QuestionRequestError("objective is an objective's id, or new");
      opt(argv, "--objective", objective);
      opt(argv, "--objective-text", text(body, "objective_text", 2000));
      const parent = text(body, "parent", 16);
      if (parent && !Q_ID.test(parent.toUpperCase())) throw new QuestionRequestError("parent is Q-<n>");
      opt(argv, "--parent", parent.toUpperCase());
      opt(argv, "--materiality", text(body, "materiality", 20));
      opt(argv, "--priority", text(body, "priority", 20));
      opt(argv, "--reason", text(body, "reason", 2000));
      opt(argv, "--expects", text(body, "expects", 20));
      if (body.completeness === true) argv.push("--completeness");
      opt(argv, "--suggest", text(body, "suggested_to", 64));
      opt(argv, "--deadline", text(body, "deadline", 64));
      opt(argv, "--neutral", text(body, "neutral", 4000));
      opt(argv, "--submission", text(body, "submission", 100));
      const hints = Array.isArray(body.hints) ? body.hints : [];
      if (hints.length > 20) throw new QuestionRequestError("at most 20 hints");
      for (const h of hints) {
        const o = (h ?? {}) as Record<string, unknown>;
        const ref = text(o, "ref", 2000, true);
        argv.push("--hint", ref);
        opt(argv, "--hint-value", text(o, "value", 2000));
      }
      const attachments = Array.isArray(body.attachments) ? body.attachments : [];
      if (attachments.length > 20) throw new QuestionRequestError("at most 20 attachments");
      for (const a of attachments) {
        if (typeof a !== "string" || !a.trim() || a.length > 2000) throw new QuestionRequestError("an attachment is a ref or a path in the run");
        argv.push("--attach", a.trim());
      }
      break;
    }
    case "amend": {
      argv.push(id(body, "q", Q_ID, "Q-<n>"));
      const rev = Number(body.expected_rev);
      if (!Number.isInteger(rev) || rev < 1) throw new QuestionRequestError("expected_rev is the revision the amendment was written against");
      argv.push("--expect-rev", String(rev));
      opt(argv, "--text", text(body, "text", 4000));
      opt(argv, "--why", text(body, "why", 2000));
      opt(argv, "--neutral", text(body, "neutral", 4000));
      if (body.completeness === true) argv.push("--completeness");
      else if (body.completeness === false) argv.push("--no-completeness");
      break;
    }
    case "priority":
      argv.push(id(body, "q", Q_ID, "Q-<n>"), body.priority === "urgent" ? "urgent" : "normal");
      opt(argv, "--reason", text(body, "reason", 2000));
      break;
    case "scope": {
      const target = String(body.target ?? body.q ?? "").trim().toUpperCase();
      if (!Q_ID.test(target) && !L_ID.test(target)) throw new QuestionRequestError("target is Q-<n>, or L-<n> for a lead in the triage queue");
      if (body.scope !== "in_scope" && body.scope !== "excluded") throw new QuestionRequestError("scope is in_scope or excluded");
      argv.push(target, body.scope, "--why", text(body, "why", 2000, true));
      break;
    }
    case "withdraw":
      argv.push(id(body, "q", Q_ID, "Q-<n>"), "--why", text(body, "why", 2000, true));
      break;
    case "clarify_reply":
      argv.push(id(body, "q", Q_ID, "Q-<n>"), id(body, "clarify", C_ID, "C-<n>"), text(body, "answer", 4000, true));
      break;
    case "accept": {
      argv.push(id(body, "q", Q_ID, "Q-<n>"));
      if (body.accept_as !== "bounded" && body.accept_as !== "not_determinable") throw new QuestionRequestError("accept_as is bounded or not_determinable");
      const rev = Number(body.expected_rev);
      if (!Number.isInteger(rev) || rev < 1) throw new QuestionRequestError("expected_rev is the revision accepted");
      argv.push("--as", body.accept_as, "--why", text(body, "why", 2000, true), "--expect-rev", String(rev));
      break;
    }
  }
  return { sub: action === "clarify_reply" ? "clarify-reply" : action, argv: [...argv, ...person(body)] };
}

/** "Add directive" on the Leads tab as `swarm.sh lead <id> direct …` arguments. */
export function directiveArgv(body: Record<string, unknown>): string[] {
  const argv: string[] = [];
  const q = String(body.q ?? "").trim().toUpperCase();
  if (q) {
    if (!Q_ID.test(q)) throw new QuestionRequestError("q is Q-<n>");
    argv.push("--question", q);
  } else {
    argv.push("--new-question", text(body, "new_question", 4000, true), "--new-why", text(body, "new_why", 2000, true));
  }
  argv.push("--title", text(body, "title", 200, true), "--why", text(body, "why", 2000, true), "--product", text(body, "product", 2000, true), "--acceptance", text(body, "acceptance", 2000, true));
  return [...argv, ...person(body)];
}
