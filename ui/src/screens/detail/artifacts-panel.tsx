/**
 * What the run produced. Every file under `work/` carries its sha256 here,
 * because an artifact a report quotes is only as good as the number that
 * proves the reader is looking at the same bytes.
 *
 * Two things this panel is careful about. `work/extracted/` and
 * `work/quarantine/` hold material pulled out of the evidence: it is hashed
 * and listed, and `swarm.sh package` deliberately leaves the bytes in the
 * sandbox, so the row says so rather than pretending it will travel. And a
 * file with no preview is not an empty state — for a carved executable the
 * size and the hash *are* the content.
 */
import { useCallback, useState } from "react";
import { Download, ExternalLink, FileCode2, FileImage, FileText, Files, FlaskConical, Sparkles } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Chip } from "@/components/console";
import { EvidenceRow, FileFacts, HashChip } from "@/components/evidence";
import { EmptyState, ErrorState, InlineNote, LoadingState } from "@/components/states";
import { Markdown } from "@/components/markdown";
import { Pager, usePager } from "@/components/pager";
import { api } from "@/lib/api";
import { bytes, relTime } from "@/lib/format";
import { useResource } from "@/lib/live";
import type { ArtifactEntry, ArtifactIndex, SwarmView, WorkFile } from "@/lib/types";

function KindIcon({ kind }: { kind: WorkFile["kind"] }) {
  if (kind === "html") return <FileCode2 className="size-4 text-slate" />;
  if (kind === "svg" || kind === "image") return <FileImage className="size-4 text-kelp" />;
  return <FileText className="size-4 text-ink-3" />;
}

function TextPreview({ url, path }: { url: string; path?: string }) {
  const loader = useCallback(() => fetch(url).then(async (r) => (r.ok ? r.text() : Promise.reject(new Error(`${r.status} ${r.statusText}`)))), [url]);
  const text = useResource(loader, 0, [url]);
  if (text.error && !text.data) return <ErrorState error={text.error} onRetry={text.reload} />;
  if (text.data === null) return <LoadingState label="Reading file" rows={4} />;
  // A `work/*.md` is what the swarm wrote for somebody to read — the report,
  // the flags table, the dependency map. Showing it as a monospace block
  // shows the source of a document instead of the document. The renderer is
  // the one the forensic report uses, so the two never drift.
  if (text.data && /\.mdx?$/i.test(path ?? "")) {
    return (
      <div className="max-h-[70vh] overflow-auto px-4 py-3">
        <Markdown text={text.data} />
      </div>
    );
  }
  return <pre className="max-h-[70vh] overflow-auto px-3 py-2 text-[12px] leading-[1.55] text-ink">{text.data || <span className="italic text-ink-3">(empty file)</span>}</pre>;
}

export function ArtifactsPanel({ view, selected, onSelect }: { view: SwarmView; selected: string | null; onSelect: (path: string) => void }) {
  const id = view.summary.id;
  const files = view.work;
  const output = view.sentinel_info?.output ?? null;
  const loadIndex = useCallback(() => api.artifacts(id), [id]);
  // Hashing is on demand: the extracted tree reaches gigabytes and the swarm
  // view is re-read on every change, so the index is its own request.
  const index = useResource<ArtifactIndex>(loadIndex, 0, [id]);
  const pager = usePager(files, files.length);
  const hashes = new Map<string, ArtifactEntry>((index.data?.files ?? []).map((f) => [f.path, f]));

  const visibleFirst = [...files].sort((a, b) => Number(a.name.startsWith(".")) - Number(b.name.startsWith(".")));
  const preferred =
    files.find((f) => f.path === selected) ??
    files.find((f) => f.path === output) ??
    visibleFirst.find((f) => f.kind === "html") ??
    visibleFirst.find((f) => f.kind === "svg") ??
    visibleFirst.find((f) => f.kind === "image") ??
    visibleFirst[0] ??
    null;
  const [reloadKey, setReloadKey] = useState(0);

  if (!files.length) {
    return (
      <EmptyState
        icon={<Files />}
        title="No artifacts yet"
        hint={
          <>
            Nothing under <code>work/</code>. Agents write their output there; HTML, SVG and PNG render here, text shows inline, and everything gets a sha256.
          </>
        }
      />
    );
  }

  const url = preferred ? `${api.workUrl(id, preferred.path)}${reloadKey ? `?v=${reloadKey}` : ""}` : "";
  const chosen = preferred ? hashes.get(preferred.path) : undefined;
  const unpackaged = (index.data?.files ?? []).filter((f) => !f.packaged);

  return (
    <div className="grid gap-4 lg:grid-cols-[340px_minmax(0,1fr)]">
      <aside className="space-y-2">
        <div className="flex flex-wrap items-baseline gap-2 px-1">
          <span className="label-caps">work/ ({files.length})</span>
          {index.data ? <span className="text-[11px] tabular text-ink-3">{bytes(index.data.bytes)} hashed</span> : null}
          <Button asChild variant="ghost" size="sm" className="ml-auto">
            <a href={api.dossierUrl(id, "artifacts.json")} download>
              artifacts.json
            </a>
          </Button>
        </div>
        <ul className="space-y-1">
          {pager.rows.map((f) => {
            const entry = hashes.get(f.path);
            return (
              <li key={f.path}>
                <EvidenceRow
                  path={f.name}
                  bytes={f.bytes}
                  sha={entry?.sha256 ?? null}
                  icon={<KindIcon kind={f.kind} />}
                  selected={preferred?.path === f.path}
                  onSelect={() => onSelect(f.path)}
                  meta={
                    <>
                      <span>{relTime(f.mtime)}</span>
                      {entry?.last_written_by ? <span className="font-mono">{entry.last_written_by}</span> : null}
                      {entry && entry.revisions > 1 ? <span>{entry.revisions} revisions</span> : null}
                    </>
                  }
                  tail={f.path === output ? <Badge variant="moss" title="done.output_file"><Sparkles /> output</Badge> : null}
                />
              </li>
            );
          })}
        </ul>
        <Pager page={pager.page} onPage={pager.set} onSize={pager.setSize} unit="files" />
        {unpackaged.length ? (
          <InlineNote tone="warn">
            <FlaskConical className="mr-1 inline size-3.5" />
            {unpackaged.length} file{unpackaged.length === 1 ? "" : "s"} under{" "}
            {(index.data?.unpackaged_dirs ?? []).map((d) => `work/${d}/`).join(" and ")} {unpackaged.length === 1 ? "is" : "are"} hashed
            but stay{unpackaged.length === 1 ? "s" : ""} in the sandbox: that material came out of the evidence and may be live. The
            hashes are in <code>artifacts.json</code>, so a ledger entry citing one can still be checked.
          </InlineNote>
        ) : null}
        {index.data?.skipped.length ? (
          <InlineNote tone="neutral">
            Skipped: {index.data.skipped.map((s) => `${s.path} (${s.reason})`).join(", ")}
          </InlineNote>
        ) : null}
      </aside>

      <section className="min-w-0 space-y-2">
        {preferred ? (
          <>
            <div className="card flex flex-wrap items-center gap-2 p-3">
              <KindIcon kind={preferred.kind} />
              <code className="text-[13px] font-medium text-ink">{preferred.path}</code>
              <Badge variant="outline">{preferred.kind}</Badge>
              {chosen ? <HashChip sha={chosen.sha256} /> : null}
              {chosen && !chosen.packaged ? <Chip tone="saffron">not packaged</Chip> : null}
              {preferred.path === output ? <Badge variant="moss">done.output_file{view.sentinel_info?.by ? ` · by ${view.sentinel_info.by}` : ""}</Badge> : null}
              <div className="ml-auto flex items-center gap-2">
                <Button variant="ghost" size="sm" onClick={() => setReloadKey((k) => k + 1)}>
                  Reload
                </Button>
                {/* Two intentions, two buttons. "Open in new tab" used to
                    download the file, because the route sent every type as
                    application/octet-stream; it serves inline now, and
                    ?download=1 is the one that saves. */}
                <Button asChild variant="secondary" size="sm" title="Open this file in a browser tab">
                  <a href={api.workUrl(id, preferred.path)} target="_blank" rel="noopener noreferrer">
                    <ExternalLink /> View
                  </a>
                </Button>
                <Button asChild variant="ghost" size="sm" title="Save a copy of this file">
                  <a href={`${api.workUrl(id, preferred.path)}?download=1`} download>
                    <Download /> Download
                  </a>
                </Button>
              </div>
            </div>
            <div className="card overflow-hidden">
              {preferred.kind === "html" ? (
                <iframe
                  key={url}
                  src={url}
                  title={preferred.name}
                  sandbox="allow-scripts"
                  referrerPolicy="no-referrer"
                  className="h-[70vh] w-full bg-white"
                />
              ) : preferred.kind === "svg" || preferred.kind === "image" ? (
                <div className="grid min-h-[40vh] place-items-center bg-[repeating-conic-gradient(var(--color-paper-2)_0%_25%,var(--color-card)_0%_50%)] bg-[length:24px_24px] p-6">
                  <img key={url} src={url} alt={preferred.name} className="max-h-[70vh] max-w-full rounded-sm shadow-card" />
                </div>
              ) : preferred.kind === "binary" ? (
                <FileFacts
                  path={preferred.path}
                  bytes={preferred.bytes}
                  sha={chosen?.sha256 ?? null}
                  kind="binary"
                  note="The browser cannot render this type, so there is nothing to show inline. The size and the hash are what a reader needs to confirm they have the same file; download it to open it in a tool that can."
                  actions={
                    <Button asChild variant="secondary" size="sm">
                      <a href={`${api.workUrl(id, preferred.path)}?download=1`} download>
                        <Download /> Download
                      </a>
                    </Button>
                  }
                />
              ) : (
                <TextPreview url={url} path={preferred.path} />
              )}
            </div>
            {preferred.kind === "html" ? (
              <p className="text-[11.5px] text-ink-3">HTML runs in a sandboxed iframe (scripts on, same-origin and network off) so agent output cannot call this app or the internet.</p>
            ) : null}
          </>
        ) : null}
      </section>
    </div>
  );
}
