/**
 * Opening a file an agent could have put there, the one way the host's
 * readers do it: as a regular file, never through a link (O_NOFOLLOW), never
 * waiting on a FIFO or a device someone left in its place (O_NONBLOCK), and
 * judged by fstat after the open, so a file swapped in between is what is
 * judged. Custody, the artifact index and the console's file routes all read
 * agent-written trees with these.
 *
 * Paths may be Buffers: an evidence name that is not valid UTF-8 (a legacy
 * code page, an extracted archive) is opened by its bytes, not by the
 * replacement characters a string would carry.
 */
import { createHash, randomBytes, type Hash } from "node:crypto";
import { closeSync, constants as fsConstants, fsyncSync, openSync, renameSync, rmSync, writeSync } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { join } from "node:path";

export type Handle = Awaited<ReturnType<typeof open>>;
export type PathLike = string | Buffer;

/** Something that can say the time is up: custody's deadline, or never. */
export type Expiry = { readonly over: boolean };

export type OpenedRegular = { handle: Handle; size: number; mtime: Date };

export async function openRegular(path: PathLike): Promise<OpenedRegular | { why: string }> {
  let lst;
  try {
    lst = await lstat(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return { why: code === "ENOENT" || code === "ENOTDIR" ? "missing" : `unreadable (${code ?? "error"})` };
  }
  if (lst.isSymbolicLink()) return { why: "a link" };
  if (!lst.isFile()) return { why: "not a regular file" };
  let handle: Handle;
  try {
    handle = await open(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return { why: code === "ELOOP" ? "a link" : code === "ENOENT" ? "missing" : `unreadable (${code ?? "error"})` };
  }
  const st = await handle.stat();
  if (!st.isFile()) {
    await handle.close();
    return { why: "not a regular file" };
  }
  return { handle, size: st.size, mtime: st.mtime };
}

/** A regular file's text, whole; the reason when it is not one or is too large to hold. */
export async function readRegularText(path: PathLike, maxBytes: number): Promise<{ text: string } | { why: string }> {
  const opened = await openRegular(path);
  if ("why" in opened) return opened;
  try {
    if (opened.size > maxBytes) return { why: `over ${maxBytes} bytes` };
    return { text: await opened.handle.readFile("utf8") };
  } finally {
    await opened.handle.close();
  }
}

export type Digests = { sha256: string; size: number; mtime: Date; md5?: string; sha1?: string };

/** How often a long read says how far it is. */
export const PROGRESS_EVERY_BYTES = 4 * 1024 * 1024 * 1024;

/**
 * A regular file hashed in full through the handle that was checked:
 * sha256 always, md5 and sha1 when asked (the digests an imager's log and an
 * opposing expert's tools carry), all in the one read. Null when `expiry`
 * says the time is up before the end; the reason when it is not a regular
 * file. `progress` is told the bytes read every PROGRESS_EVERY_BYTES, so a
 * multi-terabyte image is not an hour of silence.
 */
export async function hashRegularFile(
  path: PathLike,
  options: { expiry?: Expiry; md5?: boolean; sha1?: boolean; progress?: (bytesRead: number, size: number) => void } = {},
): Promise<Digests | { why: string } | null> {
  const opened = await openRegular(path);
  if ("why" in opened) return opened;
  try {
    const sha256 = createHash("sha256");
    const md5: Hash | null = options.md5 ? createHash("md5") : null;
    const sha1: Hash | null = options.sha1 ? createHash("sha1") : null;
    let read = 0;
    let nextSay = PROGRESS_EVERY_BYTES;
    for await (const chunk of opened.handle.createReadStream({ autoClose: false, highWaterMark: 4 * 1024 * 1024 })) {
      const buf = chunk as Buffer;
      sha256.update(buf);
      md5?.update(buf);
      sha1?.update(buf);
      read += buf.length;
      if (options.progress && read >= nextSay) {
        options.progress(read, opened.size);
        nextSay += PROGRESS_EVERY_BYTES;
      }
      if (options.expiry?.over) return null;
    }
    return {
      sha256: sha256.digest("hex"),
      size: opened.size,
      mtime: opened.mtime,
      ...(md5 ? { md5: md5.digest("hex") } : {}),
      ...(sha1 ? { sha1: sha1.digest("hex") } : {}),
    };
  } finally {
    await opened.handle.close();
  }
}

/**
 * Write `name` in `dir` so that nothing already at that name is followed:
 * the bytes go to a fresh file (O_CREAT|O_EXCL|O_NOFOLLOW, a random name),
 * which is then renamed over `name`. A rename replaces a link at the
 * destination; it never writes through it. Synchronous on purpose: it is
 * also what writes a verdict from a timer when every I/O thread is held.
 */
export function writeFileNoFollowSync(dir: string, name: string, text: string, mode = 0o644): void {
  const tmp = join(dir, `.${name}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_NOFOLLOW, mode);
  try {
    const buf = Buffer.from(text, "utf8");
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    fsyncSync(fd);
  } catch (err) {
    closeSync(fd);
    rmSync(tmp, { force: true });
    throw err;
  }
  closeSync(fd);
  try {
    renameSync(tmp, join(dir, name));
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
}
