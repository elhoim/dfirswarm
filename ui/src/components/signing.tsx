/**
 * The pieces every signing screen shares: the dialog that takes a secret in
 * the form the key wants (a passphrase; a touch and, when the key asks, a
 * PIN; an e-signature token's PIN), the note that says why this console
 * cannot sign right now, and the sha256 of bytes as the browser holds them.
 *
 * The secret lives in this dialog's state only while it is open, goes to the
 * server once (over loopback, with the token), and is cleared when the dialog
 * closes whatever happened. SECURITY.md says what a passphrase typed into a
 * browser trusts and what it proves.
 */
import { useEffect, useRef, useState, type ReactNode } from "react";
import { Fingerprint, KeyRound, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { InlineNote } from "@/components/states";
import type { SigningAvailability } from "@/lib/types";

export type KeyKind = "ssh" | "fido" | "pkcs11";

/** The sha256 of bytes the browser holds, hex: what "shown" means. */
export async function sha256Hex(bytes: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Why this console cannot sign, and the command line that can. */
export function SigningUnavailable({ signing, command }: { signing: SigningAvailability; command: string }) {
  if (signing.ok) return null;
  return (
    <InlineNote tone="warn">
      {signing.why} On the command line: <code className="[overflow-wrap:anywhere]">{command}</code>
    </InlineNote>
  );
}

/**
 * The secret dialog. `kind` decides what is asked: an ssh key's passphrase;
 * for a FIDO key a touch (and the PIN when `pin` says the key wants one); for
 * an e-signature token its PIN. `onSubmit` gets the secret ("" for a FIDO key
 * with no PIN) and the dialog clears it on the way out.
 */
export function SecretDialog({
  open,
  onOpenChange,
  kind,
  pin,
  title,
  description,
  busy,
  error,
  onSubmit,
  children,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  kind: KeyKind;
  /** A FIDO key made with verify-required wants its PIN as well as a touch. */
  pin?: boolean;
  title: string;
  description: ReactNode;
  busy: boolean;
  error: string | null;
  onSubmit: (secret: string) => void;
  children?: ReactNode;
}) {
  const [secret, setSecret] = useState("");
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!open) setSecret("");
  }, [open]);
  const asks = kind === "ssh" || kind === "pkcs11" || (kind === "fido" && pin);
  const label = kind === "pkcs11" ? "The e-signature token's PIN" : kind === "fido" ? "The FIDO key's PIN" : "The key's passphrase";
  const submit = () => {
    const s = secret;
    setSecret("");
    onSubmit(s);
  };
  return (
    <Dialog open={open} onOpenChange={(o) => (busy ? undefined : onOpenChange(o))}>
      <DialogContent aria-describedby={undefined} onOpenAutoFocus={(e) => (asks ? (e.preventDefault(), ref.current?.focus()) : undefined)}>
        <DialogTitle className="flex items-center gap-2">
          {kind === "fido" ? <Fingerprint className="size-4" /> : kind === "pkcs11" ? <ShieldCheck className="size-4" /> : <KeyRound className="size-4" />}
          {title}
        </DialogTitle>
        <DialogDescription asChild>
          <div className="space-y-2">{description}</div>
        </DialogDescription>
        {children}
        <form
          className="mt-3 space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            if (!busy && (!asks || secret)) submit();
          }}
        >
          {asks ? (
            <div className="space-y-1.5">
              <Label htmlFor="signing-secret">{label}</Label>
              <Input ref={ref} id="signing-secret" type="password" autoComplete="off" spellCheck={false} value={secret} onChange={(e) => setSecret(e.target.value)} disabled={busy} />
            </div>
          ) : null}
          {kind === "fido" ? <InlineNote tone="neutral">Touch the FIDO key every time it blinks, once the request is sent (making a key takes two touches, sometimes three). It has to be plugged into this computer, the one the console runs on.</InlineNote> : null}
          {error ? <InlineNote tone="danger">{error}</InlineNote> : null}
          <div className="flex justify-end gap-2">
            <Button type="button" variant="secondary" disabled={busy} onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={busy || (asks && !secret)}>
              {busy ? (kind === "fido" ? "Waiting for the touch…" : "Signing…") : "Sign"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
