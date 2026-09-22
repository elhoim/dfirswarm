import { ArtifactTable, TooltipProvider } from "dfirswarm";

const FILES = [
  { path: "work/report.md", bytes: 18510, sha256: "7c04b2672e668fd2012de71fbc2e5938a5e819a85ec6f838e182e40f3bd41844", packaged: true },
  { path: "work/timeline.csv", bytes: 4207, sha256: "f9b30696061a4c1f8f2b6f0a9c3d1e77a5b4c2d9e8f7a6b5c4d3e2f1a0b9c8d7", packaged: true },
  { path: "work/extracted/upload.aspx", bytes: 2048, sha256: "63cc986dec2958e367b2344c1e8bbafe64f9f7f7e5fdb4ecaafe2b75ec9449c9", packaged: false },
  {
    path: "work/extracted/SOFTWARE",
    bytes: 39845888,
    sha256: "86abc66f0e8a5d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4",
    packaged: false,
    note: "carved from the image",
  },
];

/** Every file, its size, its hash, and whether it travelled with the package. */
export const Produced = () => (
  <TooltipProvider>
    <ArtifactTable files={FILES} />
  </TooltipProvider>
);

/**
 * A file nobody hashed is the one row a reader cannot check a copy against,
 * so it is marked rather than left as an empty cell.
 */
export const NotHashed = () => (
  <TooltipProvider>
    <ArtifactTable
      files={[FILES[0], { path: "work/.browser/shot-03.png", bytes: 204800, packaged: true }]}
    />
  </TooltipProvider>
);

/** A run that wrote nothing says so, and says why that is not an error. */
export const NothingProduced = () => (
  <TooltipProvider>
    <ArtifactTable files={[]} />
  </TooltipProvider>
);
