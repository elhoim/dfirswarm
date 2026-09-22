/**
 * One table for "what kind of file is this", used by the console's work/
 * list and by the artifact index. They used to drift on the first commit:
 * the index treated `.jsonl` as text and the console treated it as binary.
 */
import { extname } from "node:path";

export type ArtifactKind = "html" | "svg" | "image" | "text" | "json" | "binary";

const KIND_BY_EXT: Array<[ArtifactKind, string[]]> = [
  ["html", [".html", ".htm"]],
  ["svg", [".svg"]],
  ["image", [".png", ".jpg", ".jpeg", ".gif", ".webp"]],
  ["json", [".json"]],
  ["text", [".txt", ".md", ".css", ".js", ".ts", ".csv", ".log", ".py", ".sh", ".jsonl", ".yaml", ".yml", ".xml", ""]],
];

export function artifactKind(name: string): ArtifactKind {
  const ext = extname(name).toLowerCase();
  for (const [kind, exts] of KIND_BY_EXT) {
    if (exts.includes(ext)) return kind;
  }
  return "binary";
}
