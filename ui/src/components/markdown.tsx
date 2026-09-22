/**
 * A swarm's Markdown, rendered.
 *
 * `work/report.md`, `work/flags.md` and `work/dependencies.md` are documents
 * written for a person to read, and the console used to show them as a
 * monospace block — the source of a document instead of the document. This
 * uses the same renderer as the forensic report (`ui/src/lib/markdown.ts`,
 * which `scripts/report.ts` imports), so a file reads the same in the console
 * and in the PDF that leaves the building.
 *
 * The HTML comes from our own renderer over the run's own files, not from the
 * network, and everything the renderer does not recognise it escapes — so
 * what reaches `dangerouslySetInnerHTML` is markup this module produced.
 */
import { markdownToHtml } from "@/lib/markdown";
import { cn } from "@/lib/utils";

export function Markdown({ text, className }: { text: string; className?: string }) {
  if (!text.trim()) return <p className="m-0 italic text-ink-3">(empty file)</p>;
  return (
    <div
      className={cn(
        "md text-[13.5px] leading-[1.6] text-ink",
        // The document's own typography, kept close to the report's: serif
        // headings, a tight table, code that wraps instead of pushing the
        // panel sideways.
        "[&_h1]:mb-2 [&_h1]:mt-0 [&_h1]:font-serif [&_h1]:text-[22px] [&_h1]:font-normal [&_h1]:leading-tight",
        "[&_h2]:mb-1.5 [&_h2]:mt-6 [&_h2]:border-b [&_h2]:border-line [&_h2]:pb-1 [&_h2]:font-serif [&_h2]:text-[17px] [&_h2]:font-normal",
        "[&_h3]:mb-1 [&_h3]:mt-5 [&_h3]:font-serif [&_h3]:text-[15px] [&_h3]:font-normal",
        "[&_h4]:mb-1 [&_h4]:mt-4 [&_h4]:text-[13.5px] [&_h4]:font-semibold",
        "[&_p]:my-2 [&_ul]:my-2 [&_ol]:my-2 [&_ul]:pl-5 [&_ol]:pl-5 [&_li]:my-1",
        "[&_ul]:list-disc [&_ol]:list-decimal",
        "[&_a]:text-kelp-ink [&_a]:underline",
        "[&_code]:rounded [&_code]:bg-paper-2 [&_code]:px-1 [&_code]:py-px [&_code]:font-mono [&_code]:text-[12px] [&_code]:break-all",
        "[&_pre]:my-2 [&_pre]:overflow-x-auto [&_pre]:rounded-lg [&_pre]:border [&_pre]:border-line [&_pre]:bg-paper-2 [&_pre]:p-3",
        "[&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_pre_code]:text-[11.5px] [&_pre_code]:break-normal",
        "[&_blockquote]:my-2 [&_blockquote]:border-l-2 [&_blockquote]:border-line-2 [&_blockquote]:pl-3 [&_blockquote]:text-ink-2",
        "[&_hr]:my-4 [&_hr]:border-line",
        "[&_table]:my-3 [&_table]:w-full [&_table]:table-fixed [&_table]:border-collapse [&_table]:text-[12.5px]",
        "[&_th]:border-b [&_th]:border-line-2 [&_th]:px-2 [&_th]:py-1.5 [&_th]:text-left [&_th]:align-bottom [&_th]:text-[11px] [&_th]:uppercase [&_th]:tracking-wider [&_th]:text-ink-3",
        "[&_td]:border-b [&_td]:border-line [&_td]:px-2 [&_td]:py-1.5 [&_td]:align-top [&_td]:break-words",
        "[&_strong]:font-semibold [&_em]:italic",
        className,
      )}
      dangerouslySetInnerHTML={{ __html: markdownToHtml(text) }}
    />
  );
}
