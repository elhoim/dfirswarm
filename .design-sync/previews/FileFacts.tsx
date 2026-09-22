import { Button, FileFacts } from "dfirswarm";

/**
 * What a file with no preview gets. It is not an empty state: for a carved
 * executable or a registry hive, the size and the hash *are* the content.
 */
export const Binary = () => (
  <FileFacts
    path="work/extracted/SOFTWARE"
    bytes={39_845_888}
    kind="binary"
    sha="63cc986dec2958e367b2344c1e8bbafe64f9f7f7e5fdb4ecaafe2b75ec9449c9"
    note="No inline preview for this type. The size and the hash are what a reader needs to confirm they have the same file; open it in a new tab to download the bytes."
    actions={<Button variant="secondary" size="sm">Open in new tab</Button>}
  />
);

/** Before the index has run, the facts are what there are. */
export const NotHashedYet = () => (
  <FileFacts path="work/extracted/carved-0x1f4.bin" bytes={20_480} kind="binary" sha={null} />
);
