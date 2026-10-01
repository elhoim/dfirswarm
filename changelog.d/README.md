# Changelog fragments

A pull request's changelog entry: `changelog.d/<branch-slug>.md`, the branch
name with `/` as `-`. One or more `### Added: …`, `### Changed: …` or
`### Fixed: …` sections, written as the entries in `CHANGELOG.md` are.
`scripts/changelog.ts --fold --release X.Y.Z` folds them into `CHANGELOG.md`
when a release is cut. See CONTRIBUTING.md, "The changelog".
