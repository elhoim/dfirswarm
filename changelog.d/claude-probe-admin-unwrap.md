### Fixed: a supplied program's test and the job images' capability probes read the hub's answer

- `supply-probe.ts` and `image-capabilities.ts` read a board function's answer
  through the hub's admin socket without taking off its `{ ok, result }`
  envelope. Every test job the hub accepted looked refused with no reason: a
  supplied ffmpeg whose known-answer test passed was posted to every seat as
  not working (a BLOCKER), and each job image's capability probe was recorded
  as "the probe job was not accepted". Both now call through one `adminCall`
  that takes the envelope off and keeps the hub's reason on a refusal.
- Tests hold the real hub's envelope (`vm-hub.test.ts`) and the probe's fake
  admin socket now answers in it (`supply-probe.test.ts`).
