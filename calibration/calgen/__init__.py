"""The calibration case generator's parts: a seeded random source, a
deflate/gzip writer, a FAT16 image builder, the three cases and the checks
that hold each planted fact to the bytes. Nothing here imports anything
outside the Python standard library, so it runs wherever python3 does."""

GENERATOR_VERSION = 1
