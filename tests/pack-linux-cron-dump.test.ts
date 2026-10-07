/**
 * The Linux pack: cron_dump, against crontab(5) lines and systemd.timer(5) and systemd.unit(5) files.
 * Every fixture is built by the test from the format's own layout, never from a tool's output.
 *
 * The tools that read command lines, messages or environments follow the secret-safe output pattern of
 * recovery_key_scan (docs/packs.md, "Secrets and sensitive output"): the answer is locators and structured
 * fields, and the text is written only on request, only in a job, only to a file under $OUT. What the answer
 * and the files it names hold is checked here for a planted secret.
 */
import assert from "node:assert/strict";
import { readFile, stat, truncate } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { CRON, IS_ROOT, SHELL, asJob, body, everythingBut, lines, put, refused, rowsOf, tool, withCwd } from "./linux-pack-harness.ts";
import type { Json } from "./linux-pack-harness.ts";

const CRON_SECRET = "s3cretCronValue99";
const SPOOL_SECRET = "abcdef123456tokenvalue";

test("cron_dump keeps every assignment of a timer in order, the empty one that resets a list included, with its section and line", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/systemd/system/backup.timer", "[Unit]\nDescription=Nightly backup\n\n[Timer]\nOnCalendar=daily\nOnCalendar=\nOnCalendar=*-*-* 02:00:00\nPersistent=true\nUnit=other.service\nUnit=backup.service\n\n[Install]\nWantedBy=timers.target\n");
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    const timer = (await rowsOf(cwd, out, "entries")).find((e) => e.source === "systemd");
    assert.ok(timer);
    const calendars = timer.assignments.filter((a: Json) => a.key === "OnCalendar");
    assert.deepEqual(calendars.map((a: Json) => [a.line, a.section, a.value]), [[5, "Timer", "daily"], [6, "Timer", ""], [7, "Timer", "*-*-* 02:00:00"]]);
    assert.deepEqual(timer.assignments.map((a: Json) => a.line), [2, 5, 6, 7, 8, 9, 10, 13]);
    assert.equal(timer.assignments.at(-1).section, "Install");
    assert.equal(timer.derived_basis.includes("not applied"), true, "the convenience fields say that empty assignments and drop-ins are not applied");
    assert.equal(timer.unit, "backup.service");
  });
});

test("cron_dump computes its coverage before it filters, so a filtered-out error still shows", async () => {
  await withCwd(async (cwd) => {
    if (IS_ROOT) return; // root reads a mode-000 file; the case needs a refused read
    const root = join(cwd, "work", "root");
    await put(root, "etc/cron.d/keep", "*/5 * * * * root /usr/bin/true\n");
    await put(root, "etc/systemd/system/locked.timer", "[Timer]\nOnBootSec=1min\n", 0o000);
    const out = body(await tool(CRON, cwd, { root: "work/root", contains: "usr/bin/true" }));
    assert.equal(out.entries_matched, 1);
    assert.equal(out.entries_total, 1, "an unreadable file is a read error, not an entry");
    assert.equal(out.all_checked_locations_read, false);
    assert.ok(out.read_errors.some((e: Json) => String(e.file).endsWith("locked.timer")));
    assert.equal("complete" in out, false);
  });
});

test("cron_dump names a scheduling file too large to read whole, and does not call the root fully read", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/cron.d/keep", "*/5 * * * * root /usr/bin/true\n");
    await put(root, "etc/cron.d/huge", "");
    await truncate(join(root, "etc/cron.d/huge"), 70 * 1024 * 1024);
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    assert.ok(out.read_errors.some((e: Json) => String(e.file).endsWith("huge") && /larger than/.test(e.error)));
    assert.equal(out.all_checked_locations_read, false);
    assert.equal(out.entries_total, 1);
  });
});

test("cron_dump looks in the user's own systemd directories and says what it did not look in", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nsvc:x:998:998::/var/lib/svc:/usr/sbin/nologin\n");
    await put(root, "home/alice/.config/systemd/user/sync.timer", "[Timer]\nOnCalendar=hourly\n");
    await put(root, "var/lib/svc/.config/systemd/user/job.timer", "[Timer]\nOnBootSec=5min\n");
    await put(root, "root/.config/systemd/user/r.timer", "[Timer]\nOnStartupSec=1min\n");
    await put(root, "etc/systemd/user/shared.timer", "[Timer]\nOnCalendar=weekly\n");
    await put(root, "etc/systemd/system/x.timer.d/override.conf", "[Timer]\nOnCalendar=\nOnCalendar=minutely\n");
    await put(root, "etc/systemd/system/x.timer", "[Timer]\nOnCalendar=daily\n");
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    const files = (await rowsOf(cwd, out, "entries")).map((e) => String(e.file).replace(/^.*work\/root\//, ""));
    for (const f of ["home/alice/.config/systemd/user/sync.timer", "var/lib/svc/.config/systemd/user/job.timer", "root/.config/systemd/user/r.timer", "etc/systemd/user/shared.timer"]) {
      assert.ok(files.includes(f), `${f} is listed: ${files.join(", ")}`);
    }
    const sync = (await rowsOf(cwd, out, "entries")).find((e) => String(e.file).endsWith("sync.timer"));
    assert.equal(sync.manager, "user");
    assert.equal(out.home_source, "etc/passwd");
    assert.ok(out.unmerged_dropins.some((d: Json) => String(d.file).endsWith("x.timer.d/override.conf")), "a drop-in is listed, not merged");
    assert.ok(out.unsupported.length >= 3, "what is not read is named");
    assert.ok(out.unsupported.some((u: string) => /at/.test(u)));
    assert.ok(out.locations.every((l: Json) => typeof l.path === "string" && typeof l.state === "string"), "a census of every place looked in");
    assert.ok(out.locations.some((l: Json) => l.state === "missing"));
  });
});

test("cron_dump keeps the cron line and its command as written, and answers without the command or the environment values", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(
      root,
      "etc/crontab",
      lines("SHELL=/bin/sh", `DB_PASSWORD=${CRON_SECRET}`, "# m h dom mon dow user command", "17 * * * * root cd / && run-parts --report /etc/cron.hourly", "*/5 * * * *   root   /usr/bin/backup   --target  /srv/data", "@reboot root /opt/x/start.sh"),
    );
    await put(root, "var/spool/cron/crontabs/alice", `*/10 * * * * /home/alice/bin/sync.sh --token=${SPOOL_SECRET}\n`);
    const run = await tool(CRON, cwd, { root: "work/root", limit: 1 });
    const out = body(run);
    const rows = await rowsOf(cwd, out, "entries");
    const backup = rows.find((e) => e.line === 5);
    assert.equal(backup.schedule, "*/5 * * * *");
    assert.equal(backup.user, "root");
    assert.equal(backup.file_modified.length > 0, true);
    assert.ok(backup.command_bytes === "/usr/bin/backup   --target  /srv/data".length);
    assert.deepEqual(backup.environment_keys, ["SHELL", "DB_PASSWORD"]);
    assert.ok(!("command" in backup) && !("environment" in backup) && !("raw_line" in backup));
    const all = await everythingBut(cwd, run.stdout, []);
    assert.ok(!all.includes(CRON_SECRET) && !all.includes(SPOOL_SECRET), "no environment value and no command text in the answer or the files it names");
    assert.match(refused(await tool(CRON, cwd, { root: "work/root", write_text: true })).error, /outside a job/);
    const job = body(await asJob(CRON, cwd, { root: "work/root", write_text: true }));
    const text = (await readFile(join(cwd, "out", "cron-text.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    const row = text.find((t) => t.line === 5);
    assert.equal(row.command, "/usr/bin/backup   --target  /srv/data", "the command is the exact substring of the line, spacing and all");
    assert.equal(row.raw_line, "*/5 * * * *   root   /usr/bin/backup   --target  /srv/data");
    assert.equal(row.environment.DB_PASSWORD, CRON_SECRET);
    assert.ok(text.find((t) => t.user === "alice").command.includes(SPOOL_SECRET));
    assert.equal(job.text.written, text.length);
    assert.equal((await stat(join(cwd, "out", "cron-text.jsonl"))).mode & 0o777, 0o600);
  });
});

test("cron_dump says a file's mtime contrast is a lead and not a conclusion, and counts the cron lines it could not read", async () => {
  await withCwd(async (cwd) => {
    const root = join(cwd, "work", "root");
    await put(root, "etc/cron.d/odd", "this is not a cron line\n*/5 * * * * root /bin/true\n");
    const out = body(await tool(CRON, cwd, { root: "work/root" }));
    assert.doesNotMatch(out.note, /on its own/);
    assert.match(out.note, /corroborat/i);
    assert.equal(out.unparsed_lines, 1);
    assert.equal((await rowsOf(cwd, out, "unparsed"))[0].line, 1);
    assert.match(String(out.coverage_note), /candidate|not the effective/i);
  });
});
