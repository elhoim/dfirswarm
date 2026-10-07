---
id: logs/hunting
title: Rule-based event review and detection coverage
when: You need to search collected logs with a documented ruleset and interpret matches and bounded negatives.
needs: [logs/security]
tools: [sigma_hunt, evtx_query, evtx_carve]
requires_host: [zircolite, hayabusa]
---

Querying by event id answers a question you already knew to ask; a ruleset tests
patterns you did not think of. Two engines can run it, and either is enough: `zircolite`
and `hayabusa` (the pack's requirements pin Zircolite 4.0.0 and Hayabusa 4.1.0, as of
October 2026; the answer's `engine_version` is the one that ran). Both are optional
programs: when the host has neither, `sigma_hunt` says so, and the report line is that
no rule-based sweep was performed, not that nothing was found.

    sigma_hunt  path=<evtx file or directory>  rules=<ruleset>  min_level=informational
                out_dir=work/<your id>/hunt

**Run it so it can be repeated.**
- Name the engine (`engine`), the evidence path, a ruleset (`rules`) and an `out_dir`
  under `work/<your id>/` (in a job, under `{OUT}`). Each call writes its own
  `hunt-<UTC time>-<id>` directory, so a result is never an earlier run's.
- Name the ruleset. `ruleset` in the answer carries its sha256 (a directory by its
  sorted paths and file digests). With no `rules`, the engine's bundled rules run and
  their content is not recorded: say that, because the sweep then cannot be repeated
  from the record. An engine without a usable ruleset is an unperformed sweep.
  Rulesets and their field mappings are engine-specific: check what the engine
  accepts in its help.
- Keep what the answer names: the engine's whole result (`result_file`), stdout,
  stderr and logs, the `command`, `exit_code`, and `detections.jsonl` (`all_detections`).
  The engine's output is where it says how many rules it loaded and skipped and how
  many records it read, where it prints them; the tool does not count those.
- `status` is `partial` when the engine exited non-zero, hit `timeout_seconds`, or a
  line of its result could not be read (`malformed_lines`, kept whole in a file).
  A partial run bounds every negative.
- `min_level` is a filter on `detections.jsonl`: what it removed is `below_min_level`,
  and stays in the engine's own result. A level the tool does not know is kept, shown
  first and counted under `unknown_levels`. Run once at `informational` so that no
  level is dropped from the normalised file, then read by level and by case question.

**A detection is a hypothesis with a name.** The evidence is the record. Take the
computer, channel and `record_id` of the row to `evtx_query` (`start_record` and
`end_record` the same id, on the file the channel lives in), read the whole record, and
cite that. Take the time from the record, not from the engine's field: its zone and
format are the engine's. A rule title is the engine's opinion. Severity is not
confidence: a low-level rule can be decisive and a critical one a false positive.
Community rules are written for live estates; an administrator doing their job trips
many. For each detection that matters, write down the benign explanation you tested
and what ruled it in or out, not the level it was dismissed at. A count of detections
measures nothing.

**What a clean result covers.** An empty or short result has several explanations, and
the report says which you excluded: no matching activity; the channel that would
record it was off, rolled over or not supplied (`logs/security`); the rule does not
exist, or does not map to the fields this log carries (a rule for a source this host
never had cannot fire); the engine could not read a file or a record (compare the
engine's record count with `records_examined` from `evtx_query` on the same file);
filtering; or a failed run. Say which channels and files were swept, the interval they
cover, the engine, its version, the ruleset digest and the filtering threshold.

**Bounded negative.** "No detection at or above <min_level> was returned by <engine>
<engine_version> with <ruleset digest, or bundled rules not recorded> over <files>,
<first to last record time>; status <complete or partial>, `malformed_lines` <n>,
`unknown_levels` <n>." It shows that no loaded rule matched in what was read. It does
not show the technique was absent.

**Damaged and recovered logs.** Rules match records that exist in a readable `.evtx`.
Where a log was cleared, recover first (`logs/recovery`). `evtx_carve` returns JSON
records and their XML, not an `.evtx`, and the pack does not convert them for either
engine: read the carved XML directly, and do not rename a JSON result to `.evtx`. A
whole `.evtx` recovered from a snapshot or from a deleted file can be hunted like any
other log.

**Sensitive output.** Each detection carries every field of the record it matched,
which can include command lines and script text. Run `sigma_hunt` as a job with
`secret_output: true` when the logs may hold them; cite the record and describe the
behaviour; never write a secret's value, a fragment or a hash.

**Does not show.** A detection does not show that the technique happened, that it
succeeded, who did it or why. A result with no detections does not show that nothing
happened: it shows what these rules, in this engine, found in these records.
