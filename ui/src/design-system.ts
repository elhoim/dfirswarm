/**
 * The design system's entry point: the console's presentational components,
 * and only those.
 *
 * What is deliberately absent is the test: `AppShell` needs a router, and the
 * jobs drawer, the goal library and the model-team editor read the live event
 * stream or the HTTP API. Those are screens. Everything here renders from its
 * props alone, which is what lets it be used outside this application.
 *
 * Adding a component to `ui/src/components/` does not add it to the system.
 * Add it here.
 */

// Primitives
export { Badge } from "@/components/ui/badge";
export { Button } from "@/components/ui/button";
export { Input, Textarea } from "@/components/ui/input";
export { Select, type SelectOption } from "@/components/ui/select";
export { Label } from "@/components/ui/label";
export { Switch } from "@/components/ui/switch";
export { Dialog, DialogTrigger, DialogClose, DialogContent, DialogTitle, DialogDescription } from "@/components/ui/dialog";
export { TooltipProvider, Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";

// The console's own vocabulary
export { Chip, TagChip, Meter, FinishMeter, VitalsBand, Vital, SerifH, PhaseHead, StatusDot } from "@/components/console";
export { EmptyState, LoadingState, ErrorState, InlineNote } from "@/components/states";
export { AgentMark, BudgetBar, DarkThreadMark } from "@/components/swarm-bits";
export { ActivityStrip, ThreadPulse } from "@/components/activity-strip";
export { ReadyDot } from "@/components/model-team";

// Evidence: the pieces that put a hash in front of a reader. An input, an
// artifact and a file in the handover package all say the same thing the
// same way because they are the same components.
export { HashChip, EvidenceRow, DownloadRow, FileFacts, PrintSheet, shortHash } from "@/components/evidence";

// Reporting: the same rule one level up. Evidence puts a hash beside a file;
// these put a source and a way to verify beside a claim, and mark the claim
// that has neither. Confidence is a mark rather than a colour so the accents
// keep meaning what they mean everywhere else.
export {
  // the citation atoms
  ExhibitNo,
  ConfidenceMark,
  Provenance,
  AuthorMark,
  AuthorList,
  // the claim
  Claim,
  FindingCard,
  // the collections
  TimelineTable,
  IndicatorTable,
  Timeline,
  // exhibits
  Exhibit,
  Excerpt,
  // method, artifacts, custody, limits
  MethodStep,
  MethodList,
  ArtifactTable,
  CustodyRecord,
  Limitation,
  NotRecorded,
  // the document frame
  ReportCover,
  ReportSection,
  ReportContents,
  Verdict,
  ReportCounts,
  // helpers
  utcStamp,
  isCited,
} from "@/components/report";
