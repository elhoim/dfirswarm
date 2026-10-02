### Fixed: a stop finalises only after its hub and VMs are gone

- Hold the hub's jobs before closing Herdr panes. When a hub or VM cannot be
  stopped, keep the collector and evidence mount, record `stop_incomplete`,
  and defer trace gathering, custody, release and the stopped outcome until
  the next successful stop. Check for a live hub even with a lost pid file,
  and defer finalisation when the process lookup fails or leftover staging
  cannot be sealed.
- Exercise an incomplete stop and its retry with a real hub, collector and
  worker VM: defer custody and release while the hub is unresponsive, then
  seal its partial output and take custody once it exits.
- Seed the Questions tab's required and released states and cover requiring,
  releasing and reinstating a requirement through the web API.
- Attribute BelkaCTF #6's scenario and challenges to TODO: security alongside
  Belkasoft's event role, using the edition's credits.
- Explain that optional-build cache invalidation belongs to a regenerated
  context; retries with an existing context need `docker build --no-cache`.
  Check an image's record even when all three program probes are present.
