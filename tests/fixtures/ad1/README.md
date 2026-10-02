# A real AD1 image

`compressed.ad1` (2,197 bytes, sha256
`d88b6186b732dd7be752df52ed863bd9d2c273b1c8b2b3520e9032bfa1018a7c`) is an
AD1 logical image that FTK Imager wrote: two short text files under
`E:\AD1_test`. It is taken unchanged from Fox-IT's dissect.evidence
(`tests/_data/ad1/compressed.ad1`, https://github.com/fox-it/dissect.evidence),
whose pyproject.toml declares the licence AGPL-3.0-or-later. Copyright
Fox-IT (part of NCC Group Plc); made by its Dissect Team, dissect@fox-it.com.
NOTICE says so too.

It is test data the dissect authors made, not any case's evidence.
`tests/ad1-pack.test.ts` reads it with the base pack's `ad1-items` recipe
and `ad1_extract` tool. The synthetic images of `tests/ad1-fixture.ts`
mirror the reader's own assumptions; this one holds the reader to what FTK
Imager writes (the time keys among them).
