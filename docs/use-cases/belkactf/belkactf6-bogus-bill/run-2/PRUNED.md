# What this copy of the package leaves out

The rule comes from the first run on this case (`run/PRUNED.md`): a
handover keeps everything, and this repository does not carry the large
files an agent derived from the evidence. They are personal material from
a real person's phone and laptop image, they are reproducible from the
evidence with the commands in the trace, and they are most of the weight.

The full package is in the sandbox and in the operator's hands. What was
removed from *this copy*, with the sha256 of each file as packaged:

```
work/s83fd08/tg_strings.txt                               965 KB  0a879c19f14e0bb4…
work/s83fd07/113270.txt                                   678 KB  bb6039486be85e57…
work/s83fd07/113251.txt                                  1392 KB  8b9fae5ea9dd21c2…
work/s83fd07/113252.txt                                   343 KB  541dfa71a3728424…
work/s83fd07/113256.txt                                   520 KB  2541db95c321472c…
work/s83fd02/tg_blob_ascii.txt                            866 KB  73428fef24fcccf8…
work/s83fd04/tg_all_strings.txt                           965 KB  0a879c19f14e0bb4…
```

7 files, 5 MB. Everything else in the package is here.

## Also removed: harness noise and evidence copies

```
work/.tmp                                                 656 KB  8 files (harness/build cache)
work/.toolchain                                           672 KB  28 files (harness/build cache)
work/s83fd05/iphone_extracts                              172 KB  3 files (evidence extract)
work/s83fd04/extracted                                    608 KB  22 files (evidence extract)
```

A further 61 files, 2 MB. The trace records the command that produced each one.
