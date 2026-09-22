import { MethodList, MethodStep } from "dfirswarm";

/** One step: the tool, its version, what it was pointed at, and when. */
export const Complete = () => (
  <div style={{ maxWidth: 660 }}>
    <MethodList>
      <MethodStep
        tool="sigscan_e01"
        version="1.4.0"
        args="--image inputs/disk/web01.E01 --carve aspx,exe"
        at="2026-02-11T09:02:40Z"
        note="Carved 38 files into work/extracted/. The image itself was never written to."
      />
    </MethodList>
  </div>
);

/** Version missing: the step cannot be reproduced, so the gap is named where the version would be. */
export const NoVersion = () => (
  <div style={{ maxWidth: 660 }}>
    <MethodList>
      <MethodStep tool="evtx_filter" args="--in inputs/logs/Security.evtx --id 4624,4688" at="2026-02-11T09:44:52Z" />
    </MethodList>
  </div>
);

/** The shortest useful step: a tool and a version, nothing else recorded. */
export const Minimal = () => (
  <div style={{ maxWidth: 660 }}>
    <MethodList>
      <MethodStep tool="yara_scan" version="4.5.0" />
    </MethodList>
  </div>
);
