# The provider key comes from Pi's own store

`swarm.sh start` expects `pi /login` to have been run and passes no credential
to the agent panes. `--key-from-env` restores the old behaviour — read the key
from the shell and hand it to each pane with `--env` — for hosts with no
persistent home, such as cloud sandboxes and CI.

The key used to travel as `herdr workspace create --env DEEPSEEK_API_KEY=sk-…`,
which puts it in an argument vector any process of the same user can read while
the command runs. Nothing was written to a file, which was the rule being
protected, but argv is not private either.

This does not make the key unreachable from an agent: `cat ~/.pi/agent/auth.json`
and `env` are equally available to a shell command. What it removes is the
argv exposure, and it puts the secret in the one place whose job is holding it.
Egress control (netguard) is what actually limits where a leaked key could go.

`--key-from-env` documents its own risk in `--help`, because the cloud guide
needs it: the home directory there is recreated every session, so a stored
login does not survive.
