/**
 * The Release tab: what the run has been released as, and the examiner's
 * adoption, signed here.
 *
 * The state first: v0 is the machine's seal ("sealed", checked only as the
 * machine's, adopted by no one); each later version an enrolled examiner's
 * adoption, with the key's kind and how it was signed (from the console or
 * the command line, the consent confirmed or only presented); what verify
 * says without a register; every technical review in the report's wording.
 *
 * Then the adoption, in the order joint-r3 set: an examiner chosen from the
 * enrolled list; the report prepared once on the server and shown here, in a
 * frame with no scripts, beside the sha256 of exactly the bytes this browser
 * holds and shows; the gate's counts and the key; a box the examiner ticks,
 * "I have read the report and the answers I adopt"; then a dialog that asks
 * for what the key wants (a passphrase; a touch and maybe a PIN; the
 * e-signature PIN). Nothing is rendered again after the consent: the server
 * signs the prepared bytes or refuses.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { FileSignature } from "lucide-react";
import { Chip } from "@/components/console";
import { EmptyState, InlineNote } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { SecretDialog, SigningUnavailable, sha256Hex } from "@/components/signing";
import { api } from "@/lib/api";
import { useResource, useSwarmVersion } from "@/lib/live";
import type { ExaminersView, PreparedRelease, ReleaseStateView, SwarmView } from "@/lib/types";

const STATUS_TONE = { signed: "moss", "countersigned-after-release": "kelp", recorded: "saffron", stale: "brick", "bad-signature": "brick" } as const;

export function ReleasePanel({ view }: { view: SwarmView }) {
  const id = view.summary.id;
  const version = useSwarmVersion(id, ["ledger", "events"]);
  const [nonce, setNonce] = useState(0);
  const stateLoader = useCallback(() => api.releaseState(id), [id]);
  const state = useResource<ReleaseStateView>(stateLoader, version + nonce, [id, "release"]);
  const peopleLoader = useCallback(() => api.examiners(), []);
  const people = useResource<ExaminersView>(peopleLoader, nonce, ["examiners"]);

  const ended = !["running", "prepared", "finishing"].includes(String(state.data?.state ?? view.summary.state ?? ""));
  const adopted = (state.data?.releases ?? []).some((r) => r.state === "adopted");

  return (
    <div className="space-y-4">
      <ReleaseState state={state.data} error={state.error} />
      {state.data ? (
        ended ? (
          <AdoptForm id={id} state={state.data} people={people.data} adopted={adopted} onDone={() => setNonce((n) => n + 1)} />
        ) : (
          <InlineNote>The run is still {state.data.state}: a release is adopted and signed once it has ended and custody is taken.</InlineNote>
        )
      ) : null}
    </div>
  );
}

function ReleaseState({ state, error }: { state: ReleaseStateView | null; error: Error | null }) {
  const [open, setOpen] = useState(false);
  if (error) return <InlineNote tone="danger">The releases could not be read: {error.message}</InlineNote>;
  if (!state) return null;
  if (!state.releases.length)
    return <EmptyState icon={<FileSignature className="size-5" />} title="No release yet" hint={<>The machine seals v0 when custody is taken at stop. An adoption prepared here writes it first when there is none.</>} />;
  return (
    <section className="card space-y-2 p-3" aria-label="Releases">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="label-caps m-0">Releases</h3>
        {state.verify ? <Chip tone={state.verify.ok ? "moss" : "brick"}>{state.verify.ok ? "every release holds" : "a release does NOT hold"}</Chip> : null}
        {state.policy.require_technical_review ? <Chip tone="kelp">a signed technical review is required ({state.policy.source})</Chip> : null}
      </div>
      <ol className="m-0 list-none space-y-1.5 p-0">
        {state.releases.map((r) => (
          <li key={r.version} className="text-[12.5px] [overflow-wrap:anywhere]">
            <span className="font-mono text-[11.5px] text-ink-3">v{r.version}</span>{" "}
            {r.error ? (
              <Chip tone="brick">{r.error}</Chip>
            ) : r.state === "adopted" ? (
              <>
                <Chip tone="moss">adopted</Chip> by {r.signer?.name ?? "?"} ({r.signer?.organisation ?? "?"}), {r.signer?.key_kind === "pkcs11" ? `e-signature certificate${r.signer.cn ? ` of ${r.signer.cn}` : ""}` : r.signer?.key_kind === "fido" ? "FIDO key" : "ssh key"} <span className="font-mono text-[11px]">{r.signer?.fingerprint}</span>
                {r.signing ? (
                  <span className="text-ink-2">
                    ; signed {r.signing.via === "console" ? "from the console" : "on the command line"}, the consent {r.signing.consent === "confirmed" ? "confirmed" : "presented (its confirmation skipped with --yes)"} at {r.signing.confirmed_at}
                  </span>
                ) : null}
              </>
            ) : (
              <>
                <Chip tone="neutral">sealed</Chip> by this install's machine key <span className="font-mono text-[11px]">{r.signer?.fingerprint}</span>
                <span className="text-ink-2">, adopted by no one: a record of what the host held ({r.reason})</span>
              </>
            )}
          </li>
        ))}
      </ol>
      <div className="space-y-1">
        <h4 className="label-caps m-0 text-[11px]">Technical review</h4>
        {state.technical.length ? (
          <ul className="m-0 list-none space-y-1 p-0 text-[12.5px]">
            {state.technical.map((t) => (
              <li key={t.review_seq} className="[overflow-wrap:anywhere]">
                <Chip tone={STATUS_TONE[t.status]}>{t.status.replace(/-/g, " ")}</Chip> {t.reviewer.name}
                {t.outcome ? `, ${t.outcome}` : ""}: {t.words}
              </li>
            ))}
          </ul>
        ) : (
          <p className="m-0 text-[12.5px] text-ink-2">No technical review.</p>
        )}
      </div>
      {state.host.isolation !== "microvm" && state.host.signer_keys_hidden !== true ? <InlineNote tone="warn">Where the run ran: {state.host.note}.</InlineNote> : null}
      {state.verify ? (
        <div>
          <button type="button" className="text-[12px] text-kelp-ink" onClick={() => setOpen((o) => !o)}>
            {open ? "hide what verify says" : "what verify says (no signer register given)"}
          </button>
          {open ? (
            <pre className="mt-1 max-h-[260px] overflow-auto whitespace-pre-wrap rounded border border-line bg-paper-2 p-2 font-mono text-[11px] leading-[1.45] [overflow-wrap:anywhere]">{state.verify.lines.join("\n")}</pre>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function AdoptForm({ id, state, people, adopted, onDone }: { id: string; state: ReleaseStateView; people: ExaminersView | null; adopted: boolean; onDone: () => void }) {
  const examiners = useMemo(() => (people?.people ?? []).filter((p) => p.role === "examiner"), [people]);
  const [examiner, setExaminer] = useState("");
  const [pdf, setPdf] = useState(false);
  const [amend, setAmend] = useState("");
  const [prepared, setPrepared] = useState<PreparedRelease | null>(null);
  const [shown, setShown] = useState<{ sha: string; url: string } | null>(null);
  const [consent, setConsent] = useState(false);
  const [busy, setBusy] = useState<"prepare" | "seal" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dialog, setDialog] = useState(false);
  const [sealError, setSealError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  useEffect(() => {
    if (!examiner && examiners.length === 1 && examiners[0].console === "ok") setExaminer(examiners[0].id);
  }, [examiners, examiner]);
  // The frame's bytes are the ones hashed: a blob of what this browser fetched, revoked when it goes.
  useEffect(() => () => (shown ? URL.revokeObjectURL(shown.url) : undefined), [shown]);

  const signing = people?.signing ?? state.signing;
  const command = `swarm.sh review ${id} --sign${examiner ? ` --examiner ${examiner}` : ""}${pdf ? " --pdf" : ""}${adopted ? " --amend-reason TEXT" : ""}`;

  const reset = useCallback(() => {
    setPrepared(null);
    setShown(null);
    setConsent(false);
    setSealError(null);
  }, []);

  const prepare = async () => {
    setError(null);
    setDone(null);
    reset();
    setBusy("prepare");
    try {
      const p = await api.prepareRelease(id, { examiner, pdf, ...(adopted ? { amend_reason: amend.trim() } : {}) });
      const res = await fetch(p.report_url, { cache: "no-store" });
      if (!res.ok) throw new Error(`the prepared report could not be read (${res.status})`);
      const bytes = await res.arrayBuffer();
      const sha = await sha256Hex(bytes);
      if (sha !== p.report.html.sha256) throw new Error(`the report this browser received (sha256 ${sha}) is not the one the server prepared (${p.report.html.sha256}): nothing will be signed`);
      setShown({ sha, url: URL.createObjectURL(new Blob([bytes], { type: "text/html" })) });
      setPrepared(p);
      // A run with no release got the machine's draft first: the state above says so now.
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const discard = async () => {
    if (prepared) await api.discardRelease(id, prepared.nonce).catch(() => undefined);
    reset();
  };

  const seal = async (secret: string) => {
    if (!prepared || !shown) return;
    setSealError(null);
    setBusy("seal");
    try {
      const r = await api.sealRelease(id, { nonce: prepared.nonce, shown_sha256: shown.sha, examiner: prepared.signer.id, secret, consent: true });
      setDialog(false);
      setDone(`Release v${r.version} is sealed: ${r.line}`);
      reset();
      onDone();
    } catch (err) {
      setSealError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const options = examiners.map((p) => ({
    value: p.id,
    label: `${p.name} (${p.organisation})`,
    hint: p.console === "ok" ? p.words : `not from the console: ${p.console}`,
    meta: p.key.kind === "pkcs11" ? "e-signature" : p.key.kind === "fido" ? "FIDO" : "ssh",
    disabled: p.console !== "ok" || Boolean(p.locked_until),
  }));

  return (
    <section className="card space-y-3 p-3" aria-label="Adopt and sign">
      <div className="flex flex-wrap items-center gap-2">
        <h3 className="label-caps m-0">{adopted ? "Amend the adopted release" : "Adopt and sign"}</h3>
        <span className="text-[12px] text-ink-3">an enrolled examiner's key and secret; nothing is signed that was not shown here first</span>
      </div>
      <SigningUnavailable signing={signing} command={command} />
      {!examiners.length ? (
        <InlineNote>
          No examiner is enrolled on this install. Enrol one in <Link to="/examiners">Examiners</Link>, or on the command line: <code>swarm.sh examiner enroll --name NAME --organisation ORG --competence TEXT --generate-key</code>.
        </InlineNote>
      ) : null}
      <div className="flex flex-wrap items-end gap-2">
        <div className="min-w-[260px] flex-1 space-y-1">
          <span className="text-[12px] font-medium text-ink-2">Examiner</span>
          <Select value={examiner} onChange={(v) => (setExaminer(v), reset())} options={options} placeholder="Choose the enrolled examiner…" aria-label="Examiner" disabled={!signing.ok || busy !== null} />
        </div>
        <label className="flex items-center gap-1.5 text-[12.5px] text-ink-2">
          <input type="checkbox" className="accent-kelp" checked={pdf} onChange={(e) => (setPdf(e.target.checked), reset())} disabled={busy !== null} /> print the PDF with it
        </label>
        {adopted ? <Input value={amend} onChange={(e) => (setAmend(e.target.value), reset())} placeholder="why this amendment (required)" aria-label="Amendment reason" className="min-w-[240px] flex-1" /> : null}
        <Button variant="secondary" disabled={!signing.ok || !examiner || busy !== null || (adopted && !amend.trim())} onClick={() => void prepare()}>
          {busy === "prepare" ? "Preparing…" : "Prepare the release"}
        </Button>
      </div>
      {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
      {done ? <InlineNote tone="ok">{done}</InlineNote> : null}
      {prepared && shown ? (
        <div className="space-y-3">
          <div className="grid gap-2 text-[12.5px] sm:grid-cols-2">
            <div className="space-y-0.5">
              <div className="label-caps text-[11px]">What will be signed</div>
              <div>
                release v{prepared.version}, {prepared.reason}
              </div>
              <div className="font-mono text-[11px] [overflow-wrap:anywhere]">report.html sha256 {shown.sha}</div>
              {prepared.report.markdown ? <div className="font-mono text-[11px] [overflow-wrap:anywhere]">{prepared.report.markdown.path} sha256 {prepared.report.markdown.sha256}</div> : null}
              {prepared.report.pdf ? <div className="font-mono text-[11px] [overflow-wrap:anywhere]">report.pdf sha256 {prepared.report.pdf.sha256}</div> : null}
              <div className="text-ink-3">prepared {prepared.prepared_at}; it lapses at {prepared.expires_at}</div>
            </div>
            <div className="space-y-0.5">
              <div className="label-caps text-[11px]">The gate</div>
              <div>
                {prepared.gate.scope === "answers"
                  ? `${prepared.gate.adopted} adopted, ${prepared.gate.qualified} qualified, ${prepared.gate.withdrawn} withdrawn, ${prepared.gate.inconclusive} inconclusive, ${prepared.gate.not_adopted} not adopted (the agents')`
                  : "the report as a whole (a ledger with no answer entries)"}
              </div>
              {prepared.gate.open_rejections.length ? <div>rejections standing: {prepared.gate.open_rejections.map((n) => `E-${n}`).join(", ")}</div> : null}
              <div>{prepared.technical.length ? prepared.technical.map((t) => `${t.reviewer}${t.outcome ? ` (${t.outcome})` : ""}: ${t.words}`).join("; ") : "No technical review."}</div>
              <div className="[overflow-wrap:anywhere]">
                Key: {prepared.signer.words}
                {prepared.signer.touch ? <strong>: touch your key when asked</strong> : null}
              </div>
            </div>
          </div>
          <iframe title={`Release v${prepared.version} as it will be signed`} sandbox="" src={shown.url} className="h-[560px] w-full rounded-md border border-line bg-white" />
          <label className="flex items-start gap-2 text-[13px] text-ink">
            <input type="checkbox" className="mt-0.5 accent-kelp" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
            <span>{prepared.statement}.</span>
          </label>
          <div className="flex flex-wrap gap-2">
            <Button disabled={!consent || busy !== null} onClick={() => (setSealError(null), setDialog(true))}>
              Sign release v{prepared.version}
            </Button>
            <Button variant="ghost" disabled={busy !== null} onClick={() => void discard()}>
              Discard
            </Button>
          </div>
          <SecretDialog
            open={dialog}
            onOpenChange={setDialog}
            kind={prepared.signer.kind}
            pin={prepared.signer.secret === "fido-pin"}
            title={`Sign release v${prepared.version} as ${prepared.signer.name}`}
            description={
              <>
                <p className="m-0">
                  Over report.html <span className="font-mono text-[11px] [overflow-wrap:anywhere]">{shown.sha}</span>, with {prepared.signer.words}.
                </p>
                <p className="m-0 text-ink-3">The secret goes once to this console's server, on this machine, and down a pipe to ssh-keygen or openssl; it is kept nowhere. Five wrong ones lock {prepared.signer.name} out of the console for fifteen minutes.</p>
              </>
            }
            busy={busy === "seal"}
            error={sealError}
            onSubmit={(s) => void seal(s)}
          />
        </div>
      ) : null}
    </section>
  );
}
