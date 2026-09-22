import { MethodList, MethodStep } from "dfirswarm";

/** What was run, in the order it ran. A result nobody can reproduce is the same problem as a claim nobody can check. */
export const WhatWasRun = () => (
  <div style={{ maxWidth: 660 }}>
    <MethodList>
      <MethodStep
        tool="sigscan_e01"
        version="1.4.0"
        args="--image inputs/disk/web01.E01 --carve aspx,exe"
        at="2026-02-11T09:02:40Z"
        note="Carved 38 files into work/extracted/. The image itself was never written to."
      />
      <MethodStep
        tool="usn_journal"
        version="0.9.2"
        args="--volume inputs/disk/web01.E01 --since 2026-02-10"
        at="2026-02-11T09:14:11Z"
      />
      <MethodStep
        tool="yara_scan"
        version="4.5.0"
        args="--rules catalog/webshell.yar work/extracted/"
        at="2026-02-11T09:31:07Z"
        note="Two hits, both on work/extracted/upload.aspx."
      />
    </MethodList>
  </div>
);

/** A tool whose version nobody recorded cannot be re-run, and the step says so rather than looking complete. */
export const AStepWithoutAVersion = () => (
  <div style={{ maxWidth: 660 }}>
    <MethodList>
      <MethodStep tool="evtx_filter" args="--in inputs/logs/Security.evtx --id 4624,4688" at="2026-02-11T09:44:52Z" note="Forged by the swarm during the run." />
      <MethodStep tool="yara_scan" version="4.5.0" args="--rules catalog/webshell.yar work/extracted/" at="2026-02-11T09:31:07Z" />
    </MethodList>
  </div>
);
