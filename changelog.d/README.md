# Changelog fragments

A pull request's changelog entry: `changelog.d/<branch-slug>.md`, the branch
name with `/` as `-`. One or more sections under a `### <Kind>: …` heading,
the kinds `CHANGELOG.md` uses (Added, Changed, Fixed, Security, …), written as
its entries are. Name a pack, not its version.
`scripts/changelog.ts --fold --release X.Y.Z` folds them into `CHANGELOG.md`
when a release is cut. See CONTRIBUTING.md, "The changelog".
