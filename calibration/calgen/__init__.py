"""The calibration case generator's parts: a seeded random source, a
deflate/gzip writer, a FAT16 image builder, the three cases and the checks
that hold each planted fact to the bytes. Nothing here imports anything
outside the Python standard library, so it runs wherever python3 does."""

# 2: the goal's front matter designates the brief's givens as premises.
# 3: the goal's front matter says what each question presumes (presumes:),
#    framed from the question's words alone: every question that asks which,
#    when or how of an event presumes it, whatever the truth.
GENERATOR_VERSION = 3
