### Changed: a new push to a pull request cancels the CI runs the older push left behind

`ci.yml` and `images.yml` now have a `concurrency` group per pull request, with `cancel-in-progress` on for `pull_request` events only. Before, every push to a PR branch queued three more macOS jobs behind the old ones, and the account's five concurrent macOS jobs were spent on commits nobody looked at any more. Pushes to `main`, tags, schedules and manual runs get a group of their own (the run id), so none of them is ever cancelled or replaced while pending. No harness, pack or skill file changes.
