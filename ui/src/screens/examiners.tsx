/**
 * The enrolment screen: who may sign on this install, and enrolling one
 * more.
 *
 * Each person is an examiner (adopts a report and signs its release) or a
 * technical reviewer (signs their own review), with one key: an ssh key made
 * here with a passphrase (typed twice; the console never makes one without),
 * a FIDO key made on the authenticator with a touch (and its PIN when every
 * signature should need it), or an e-signature certificate read from a
 * token without its PIN. Enrolment shows the fingerprint and, for an ssh or
 * FIDO key, the line for the organisation's signer register: the register,
 * checked in person, ties the key to the person. A certificate's issuer does
 * that for an e-signature, and the certificate travels inside every
 * signature it makes.
 */
import { useCallback, useState } from "react";
import { Chip, SerifH } from "@/components/console";
import { InlineNote } from "@/components/states";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select } from "@/components/ui/select";
import { SigningUnavailable } from "@/components/signing";
import { api } from "@/lib/api";
import { useResource } from "@/lib/live";
import type { EnrolledPerson, ExaminersView } from "@/lib/types";

const KIND_WORD = { ssh: "ssh key", fido: "FIDO key", pkcs11: "e-signature certificate" } as const;

export function ExaminersScreen() {
  const [nonce, setNonce] = useState(0);
  const loader = useCallback(() => api.examiners(), []);
  const people = useResource<ExaminersView>(loader, nonce, ["examiners"]);
  return (
    <div className="mx-auto w-full max-w-[1100px] space-y-5 px-4 py-6 sm:px-10">
      <SerifH as="h1" size={30}>
        Examiners and reviewers
      </SerifH>
      <p className="m-0 max-w-[70ch] text-[13px] text-ink-2">
        The people enrolled on this install, outside every run. An examiner adopts a report and signs its release; a technical reviewer signs their own review of it. One person is never both on one run: someone who is both enrols twice, and the same name or key is refused.
      </p>
      {people.error ? <InlineNote tone="danger">{people.error.message}</InlineNote> : null}
      <section className="card space-y-2 p-3" aria-label="Enrolled">
        <h2 className="label-caps m-0">Enrolled</h2>
        {people.data?.people.length ? (
          <ul className="m-0 list-none space-y-2 p-0">
            {people.data.people.map((p) => (
              <PersonRow key={p.id} p={p} />
            ))}
          </ul>
        ) : (
          <p className="m-0 text-[12.5px] text-ink-2">No one is enrolled on this install yet.</p>
        )}
      </section>
      {people.data ? <EnrolForm signing={people.data.signing} onDone={() => setNonce((n) => n + 1)} /> : null}
    </div>
  );
}

function PersonRow({ p }: { p: EnrolledPerson }) {
  return (
    <li className="space-y-0.5 rounded-md border border-line p-2.5 text-[12.5px]">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-ink">
          {p.name} <span className="font-mono text-[11px] text-ink-3">({p.id})</span>, {p.organisation}
        </span>
        <Chip tone={p.role === "examiner" ? "kelp" : "slate"}>{p.role}</Chip>
        <Chip tone="neutral">{KIND_WORD[p.key.kind]}</Chip>
        {p.console === "ok" ? <Chip tone="moss">signs from the console</Chip> : <Chip tone="saffron">command line only</Chip>}
        {p.locked_until ? <Chip tone="brick">locked until {p.locked_until}</Chip> : null}
      </div>
      <p className="m-0 text-ink-2">{p.competence}</p>
      <p className="m-0 font-mono text-[11px] text-ink-2 [overflow-wrap:anywhere]">{p.words}</p>
      {p.console !== "ok" ? <p className="m-0 text-[12px] text-ink-3">{p.console}</p> : null}
    </li>
  );
}

function EnrolForm({ signing, onDone }: { signing: ExaminersView["signing"]; onDone: () => void }) {
  const [role, setRole] = useState("examiner");
  const [kind, setKind] = useState("ssh");
  const [name, setName] = useState("");
  const [organisation, setOrganisation] = useState("");
  const [competence, setCompetence] = useState("");
  const [id, setId] = useState("");
  const [pass1, setPass1] = useState("");
  const [pass2, setPass2] = useState("");
  const [pin, setPin] = useState("");
  const [verifyRequired, setVerifyRequired] = useState(false);
  const [resident, setResident] = useState(false);
  const [module, setModule] = useState("");
  const [objectId, setObjectId] = useState("");
  const [chain, setChain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<{ person: EnrolledPerson; register: string | null } | null>(null);

  const clearSecrets = () => {
    setPass1("");
    setPass2("");
    setPin("");
  };
  const ready = name.trim() && organisation.trim() && competence.trim() && (kind === "ssh" ? pass1.length >= 8 && pass1 === pass2 : kind === "pkcs11" ? module.trim() && objectId.trim() : true);
  const submit = async () => {
    setBusy(true);
    setError(null);
    setDone(null);
    try {
      const r = await api.enroll({
        kind,
        role,
        name: name.trim(),
        organisation: organisation.trim(),
        competence: competence.trim(),
        ...(id.trim() ? { id: id.trim() } : {}),
        ...(kind === "ssh" ? { passphrase: pass1, passphrase_again: pass2 } : {}),
        ...(kind === "fido" ? { fido_verify_required: verifyRequired, fido_resident: resident, ...(pin ? { pin } : {}) } : {}),
        ...(kind === "pkcs11" ? { pkcs11_module: module.trim(), ...(objectId.trim().startsWith("pkcs11:") ? { pkcs11_uri: objectId.trim() } : { pkcs11_id: objectId.trim() }), ...(chain.trim() ? { pkcs11_chain: chain.trim() } : {}) } : {}),
      });
      setDone({ person: r.person, register: r.register });
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      clearSecrets();
      setBusy(false);
    }
  };
  const command = `swarm.sh examiner enroll --name NAME --organisation ORG --competence TEXT --role ${role} ${kind === "ssh" ? "--generate-key" : kind === "fido" ? "--fido" : "--pkcs11-module PATH --pkcs11-id HEX"}`;
  return (
    <section className="card space-y-3 p-3" aria-label="Enrol">
      <h2 className="label-caps m-0">Enrol</h2>
      <SigningUnavailable signing={signing} command={command} />
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-1">
          <Label>Role</Label>
          <Select value={role} onChange={setRole} aria-label="Role" options={[
              { value: "examiner", label: "Examiner", hint: "adopts a report and signs its release" },
              { value: "reviewer", label: "Technical reviewer", hint: "signs their own review of the methods" },
              { value: "analyst", label: "Analyst", hint: "adds questions to a running case; signs no release" },
              { value: "observer", label: "Observer", hint: "proposes questions for the examiner's triage" },
            ]} />
        </div>
        <div className="space-y-1">
          <Label>Key</Label>
          <Select
            value={kind}
            onChange={(v) => (setKind(v), clearSecrets())}
            aria-label="Kind of key"
            options={[
              { value: "ssh", label: "An ssh key made here", hint: "ed25519, with a passphrase typed twice" },
              { value: "fido", label: "A FIDO key", hint: "made on the authenticator plugged into this computer; a touch per signature" },
              { value: "pkcs11", label: "An e-signature certificate", hint: "on a token, read without its PIN; each signature a CAdES CMS" },
            ]}
          />
        </div>
        <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="name" aria-label="Name" />
        <Input value={organisation} onChange={(e) => setOrganisation(e.target.value)} placeholder="organisation" aria-label="Organisation" />
        <Input value={competence} onChange={(e) => setCompetence(e.target.value)} placeholder="competence: what qualifies this person" aria-label="Competence" className="sm:col-span-2" />
        <Input value={id} onChange={(e) => setId(e.target.value)} placeholder="id (optional: made from the name)" aria-label="Id" className="font-mono" />
      </div>
      {kind === "ssh" ? (
        <div className="grid gap-3 sm:grid-cols-2">
          <Input type="password" autoComplete="new-password" value={pass1} onChange={(e) => setPass1(e.target.value)} placeholder="passphrase (at least 8 characters)" aria-label="Passphrase" />
          <Input type="password" autoComplete="new-password" value={pass2} onChange={(e) => setPass2(e.target.value)} placeholder="the same passphrase again" aria-label="Passphrase again" />
          {pass2 && pass1 !== pass2 ? <p className="m-0 text-[12px] text-brick-ink sm:col-span-2">The two passphrases differ.</p> : null}
        </div>
      ) : null}
      {kind === "fido" ? (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-4 text-[12.5px] text-ink-2">
            <label className="flex items-center gap-1.5">
              <input type="checkbox" className="accent-kelp" checked={verifyRequired} onChange={(e) => setVerifyRequired(e.target.checked)} /> every signature needs the PIN too
            </label>
            <label className="flex items-center gap-1.5">
              <input type="checkbox" className="accent-kelp" checked={resident} onChange={(e) => setResident(e.target.checked)} /> resident on the authenticator
            </label>
          </div>
          {verifyRequired || resident ? <Input type="password" autoComplete="off" value={pin} onChange={(e) => setPin(e.target.value)} placeholder="the authenticator's PIN" aria-label="FIDO PIN" className="max-w-[320px]" /> : null}
          <InlineNote>Touch the key when it blinks after you press Enrol. It must be plugged into this computer, where the console runs.</InlineNote>
        </div>
      ) : null}
      {kind === "pkcs11" ? (
        <div className="grid gap-3 sm:grid-cols-2">
          <Input value={module} onChange={(e) => setModule(e.target.value)} placeholder="PKCS#11 module (e.g. /usr/local/lib/libeTPkcs11.dylib)" aria-label="PKCS#11 module" className="font-mono sm:col-span-2" />
          <Input value={objectId} onChange={(e) => setObjectId(e.target.value)} placeholder="object id in hex, or a pkcs11: URI" aria-label="Object id or URI" className="font-mono" />
          <Input value={chain} onChange={(e) => setChain(e.target.value)} placeholder="the issuing CA's certificate file (optional)" aria-label="Issuing CA certificates" className="font-mono" />
          <p className="m-0 text-[12px] text-ink-3 sm:col-span-2">The certificate is read without the PIN; its subject's identity number is never shown. The issuing CA's certificate, when given, goes into every signature so a verifier needs only the root.</p>
        </div>
      ) : null}
      {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
      {done ? (
        <InlineNote tone="ok">
          <div>
            Enrolled {done.person.name} ({done.person.id}) as {done.person.role === "examiner" ? "an examiner" : done.person.role === "reviewer" ? "a technical reviewer" : done.person.role === "analyst" ? "an analyst" : "an observer"}: {done.person.words}.
          </div>
          {done.register ? (
            <div className="mt-1">
              For the organisation's signer register (check the fingerprint with {done.person.name} in person first):
              <pre className="mt-1 whitespace-pre-wrap font-mono text-[11px] [overflow-wrap:anywhere]">{done.register}</pre>
            </div>
          ) : (
            <div className="mt-1">The certificate's issuer, not a register line, ties it to {done.person.name}: verify a signature's chain with --ca FILE.</div>
          )}
        </InlineNote>
      ) : null}
      <Button disabled={!signing.ok || !ready || busy} onClick={() => void submit()}>
        {busy ? (kind === "fido" ? "Waiting for the touch…" : "Enrolling…") : "Enrol"}
      </Button>
    </section>
  );
}
