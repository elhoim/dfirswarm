# The goal owns the definition of done

`swarm.sh start` refuses a goal with no `## Definition of done` heading, and
`await-done.sh` certifies a run only when the sentinel exists *and* every
`## Checks` line from that goal passes.

Before this, the contract template stapled `work/hello.txt` onto every swarm
and await-done checked only that file. A real goal had to smuggle its own
finish line into prose, and the harness would then certify a swarm that had
produced something else entirely — which is exactly what happened on a live
run here: the artifacts were right, but nothing verified them.

The considered alternative was a hybrid: keep the built-in check and let a
goal override it. That leaves two mental models for what "done" means and
fails quietly in the same way, so the built-in DoD was removed instead.
`prompts/goals/hello.md` keeps the original exercise as an ordinary goal file
and doubles as the worked example.

Consequence: the checks are shell commands the operator writes, and they are
read from the run registry rather than from the contract inside the sandbox —
an agent that could rewrite its own checks could certify itself. A sandbox with
no registry entry (a hand-made directory, or a custom `--sandbox` without the
matching `SWARM_RUNS_DIR`) falls back to the contract and warns that it did.
