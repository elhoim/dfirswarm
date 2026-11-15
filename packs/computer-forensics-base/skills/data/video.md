---
id: data/video
title: Every frame of a video
when: A video shows it briefly, or will not open.
card: frame_survey {"video": "<file>"} scores EVERY frame on numbered sheets: read `runs` first, then those frames at native size: {"mode": "extract", "first": N, "last": M}. every above 1 or max_frames makes it partial: a negative needs complete with every 1. A file that will not open: {"mode": "repair"}; claim only what the copy DECODES. No ffmpeg in the image: status failed, not an empty video.
needs: []
tools: [frame_survey]
requires_host: [ffmpeg, ffprobe]
---

Use when a video may show something for a moment (a caption, a screen, a code, a face) or does not play. Not for its metadata (`data/documents-media`) or its place on a phone (the mobile pack).

    job_run tool=frame_survey args={"video": "work/<you>/clip.mp4"}
    job_run tool=frame_survey args={"video": "work/<you>/clip.mp4", "mode": "extract", "first": 412, "last": 421}

1. **Survey every frame first.** The default call tiles every decoded frame with its number and time and scores it. Sampling by eye, or one frame a second, misses a stretch of ten frames.
2. **Read `runs`, then the sheets.** A run is a region that changed and changed again with no scene cut between: a candidate, from block means. `scene_cuts` and `windows_that_stand_out` are the other two leads. Look at the sheets a run names.
3. **Read text off native frames.** A tile is a reduced copy: `extract` the run's frames, then `data/glyphs` for exact characters or `data/qr` for a code. `rotation_note` says when frames are turned or mirrored as a player shows them.
4. **Partial means skipped.** `every` above 1, `max_frames`, the clock, a damaged stream, one that ends short of the duration its container states, or frames of another size (`frames_of_another_size`) make the survey `partial`, and `skipped` says what was not decoded: a negative holds for the frames decoded. `not_read_or_judged` counts each kind of gap; any count above zero is partial. Go on with `start_frame`.
5. **A file that will not open** goes to `mode: repair`: it reads the container (an MP4 with its moov missing, at the end or its data cut; an AVI without an index), writes a remuxed copy and counts the frames that copy decodes. That count is the claim. A missing moov is not rebuilt: say so, and ask for a whole file from the same recorder.
6. **`failed` with no decoder** (`ffmpeg`, `ffprobe` not installed) is not an empty video: say the video was not examined.

**Record.** The file's digest, the frame numbers and times (and whether a time is the frame's own or frame / rate), the sheets or frames cited, the decoder's version.

**Shows.** What the decoded frames hold, in decode order. **Does not show.** When or where it was recorded, that it was not edited before, or frames the decoder could not read.

**Sensitive output.** Frames can show faces, screens and credentials: cite the frame file, and run the job with `secret_output: true` when they may.
