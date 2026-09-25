/**
 * The handover, from the console.
 *
 * `docs/improvement-plan.md` B8 claimed the console linked the package and it
 * did not; this is where that becomes true. Two halves: the report as the
 * browser will print it, at paper proportions so the operator sees the
 * pagination before committing to it, and every file of the dossier with its
 * size and its sha256 beside the button that fetches it. The hash is on the
 * row for the same reason it is on the evidence: what makes this a handover
 * rather than a download is that the number travels with the file.
 *
 * One request builds that set. Fetching the HTML and the artifact index
 * separately used to walk `work/` twice, and the download rows were a
 * hardcoded list with no hash at all. The generated files (report, summary,
 * artifacts.json) are offered as blobs of those exact bytes, so the number
 * beside the button is the number of the file the button writes.
 *
 * What the handover is worth is stated next to it. The counts carry the
 * ledger's events, indicators and findings and, beside them, how many entries
 * name neither a source nor a way to check them — somebody receiving an
 * uncheckable record reads it as an assertion, and that is worth knowing
 * before the package leaves. The artifacts sit in the wide column rather than
 * the rail, because a sha256 truncated by 340px is decoration and the hash is
 * the whole point.
 */
import { useCallback, useEffect, useState } from "react";
import { FileText, Printer, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { SerifH } from "@/components/console";
import { DownloadRow, PrintSheet } from "@/components/evidence";
import { ArtifactTable, ReportCounts, isCited } from "@/components/report";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { api } from "@/lib/api";
import { bytes } from "@/lib/format";
import { useResource } from "@/lib/live";
import type { Dossier, SwarmView } from "@/lib/types";

const GENERATED = new Set(["report.html", "summary.md", "artifacts.json"]);

function blobUrlsFor(dossier: Dossier): Record<string, string> {
  return {
    "report.html": URL.createObjectURL(new Blob([dossier.html], { type: "text/html;charset=utf-8" })),
    "summary.md": URL.createObjectURL(new Blob([dossier.summary], { type: "text/markdown;charset=utf-8" })),
    "artifacts.json": URL.createObjectURL(new Blob([dossier.artifactsJson], { type: "application/json;charset=utf-8" })),
  };
}

export function ReportPanel({ view }: { view: SwarmView }) {
  const id = view.summary.id;
  const load = useCallback(() => api.dossier(id), [id]);
  const dossier = useResource<Dossier>(load, 0, [id]);
  const [blobs, setBlobs] = useState<Record<string, string>>({});

  useEffect(() => {
    if (!dossier.data) {
      setBlobs({});
      return;
    }
    const next = blobUrlsFor(dossier.data);
    setBlobs(next);
    return () => {
      for (const url of Object.values(next)) URL.revokeObjectURL(url);
    };
  }, [dossier.data]);

  const ledger = view.ledger;
  const reportHref = blobs["report.html"] ?? api.dossierUrl(id, "report.html");
  const timeline = ledger.entries.filter((e) => e.kind === "event").length;
  const iocs = ledger.entries.filter((e) => e.kind === "ioc").length;
  const findings = ledger.entries.filter((e) => e.kind === "finding").length;
  // The count that decides whether this package is worth handing over. A
  // record missing its source or its evidence cannot be checked by the person
  // receiving it, so it is counted on the handover rather than left for them
  // to discover.
  const uncited = ledger.entries.filter((e) => !isCited(e)).length;
  const files = dossier.data?.files ?? [];
  const artifacts = dossier.data?.artifacts;

  // The detail page already gives 440px to its right rail, so this panel is
  // working in a narrow column. It stacks until there is genuinely room for
  // two, rather than splitting into two columns neither of which fits.
  return (
    <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
      <section className="min-w-0 space-y-2">
        <div className="card flex flex-wrap items-center gap-2 p-3">
          <FileText className="size-4 text-slate" />
          <span className="text-[13px] font-medium text-ink">report.html</span>
          <div className="ml-auto flex items-center gap-2">
            <Button asChild variant="ghost" size="sm">
              <a href={reportHref} target="_blank" rel="noopener noreferrer">
                <ExternalLink /> Open
              </a>
            </Button>
            <Button asChild variant="secondary" size="sm">
              <a href={reportHref} download="report.html">
                <Printer /> Download
              </a>
            </Button>
          </div>
        </div>
        <ReportCounts events={timeline} indicators={iocs} findings={findings} uncited={uncited} />
        {uncited > 0 ? (
          <InlineNote tone="warn">
            {uncited} {uncited === 1 ? "entry does" : "entries do"} not say both where it was seen and how to check it. The report
            marks {uncited === 1 ? "it" : "them"} rather than dropping {uncited === 1 ? "it" : "them"}, but a reader will treat an
            uncheckable record as an assertion, not evidence. The Ledger tab shows which.
          </InlineNote>
        ) : null}
        {/*
          The report is agent-derived text rendered by the harness, so it goes
          behind the same sandbox as any other artifact: no scripts, no
          same-origin, no network. The preview is `srcdoc`, not `src`: the
          report is one self-contained file, so handing the markup straight to
          the frame is one fewer request and nothing between the console and
          the frame can refuse it.
        */}
        {dossier.error && !dossier.data ? (
          <ErrorState error={dossier.error} onRetry={dossier.reload} title="Could not render the report" />
        ) : (
          <PrintSheet>
            {dossier.data === null ? (
              <div className="grid h-full place-items-center">
                <LoadingState label="Rendering the report" rows={2} className="w-2/3" />
              </div>
            ) : (
              <iframe
                srcDoc={dossier.data.html}
                title={`Report for ${id}`}
                // The report carries no script; it needs none to render.
                sandbox=""
                referrerPolicy="no-referrer"
                className="h-full w-full border-0 bg-white"
              />
            )}
          </PrintSheet>
        )}
        <p className="text-[11.5px] text-ink-3">
          Shown at A4 proportions, which is what <code>swarm.sh report {id} --pdf</code> prints. The browser numbers the pages; this
          document asks to be cited by section.
        </p>

        {/*
          Artifacts produced — the report's own section 6, in the wide column
          because the hash is the point and a hash truncated by a 340px rail
          is decoration. The aside keeps the dossier, which is a list of links.
        */}
        <SerifH as="h3" size={20}>
          Artifacts produced
        </SerifH>
        {artifacts == null ? (
          <LoadingState label="Hashing work/" rows={3} />
        ) : artifacts.files.length === 0 ? (
          <EmptyState title="Nothing under work/" hint="This run wrote no artifacts, so the report has none to hash." />
        ) : (
          <>
            <p className="text-[12.5px] text-ink-2">
              {artifacts.files.length} file{artifacts.files.length === 1 ? "" : "s"}, {bytes(artifacts.bytes)};{" "}
              {bytes(artifacts.packaged_bytes)} of that travels with the package.
            </p>
            <ArtifactTable files={artifacts.files} />
            {artifacts.files.some((f) => !f.packaged) ? (
              <InlineNote tone="warn">
                Files held in the sandbox came out of the evidence and may be live, so the package does not carry them. Their hashes
                are in <code>artifacts.json</code>, which is what lets a reader check a copy obtained another way.
              </InlineNote>
            ) : null}
          </>
        )}
      </section>

      <aside className="space-y-3">
        <SerifH as="h3" size={20}>
          The dossier
        </SerifH>
        <p className="text-[12.5px] leading-[1.5] text-ink-2">
          What you hand over, with the hashes to prove it is what the swarm produced.{" "}
          <code>scripts/swarm.sh package {id}</code> writes all of it to <code>&lt;sandbox&gt;/package/</code> with a{" "}
          <code>MANIFEST.txt</code>.
        </p>
        {dossier.data === null && !dossier.error ? (
          <LoadingState label="Building the dossier" rows={3} />
        ) : (
          <div className="space-y-1.5">
            {files.map((f) => (
              <DownloadRow
                key={f.name}
                name={f.name}
                href={GENERATED.has(f.name) ? (blobs[f.name] ?? api.dossierUrl(id, f.name)) : api.dossierUrl(id, f.name)}
                description={f.description}
                bytes={f.bytes ?? undefined}
                sha={f.sha256}
                disabled={!f.present}
                disabledReason={f.reason}
              />
            ))}
          </div>
        )}

      </aside>
    </div>
  );
}
