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

## Whose credential, under which terms (2026-10-01)

Which credential a seat uses is a question of terms as well as of exposure.
A legal review of the providers' published terms (read 2026-10-01; it is not
legal advice, and a lawyer has not seen it) found:

- **Anthropic** does not permit Free, Pro or Max subscription (OAuth)
  credentials in a third-party client such as Pi; a product or service that
  calls Claude uses an API key under its Commercial Terms, and Anthropic may
  enforce that without notice. So an `anthropic/*` seat on a subscription
  login (an `oauth` entry in Pi's store, or `ANTHROPIC_OAUTH_TOKEN` where the
  store holds no key) is refused at kickoff in every run, whatever
  `--allow-oauth-in-vm` says, with how to log Pi in with an API key.
- **OpenAI's Codex** subscription is a ChatGPT consumer login. Its terms do
  not today forbid a third-party client, so a test or CTF run may still use
  it; its consumer terms carry no processor commitments and may let the
  provider train on what it is sent, so it is no place for a customer's
  evidence. The kickoff's `Key:` line and the record say "consumer plan; not
  for customer data" for every subscription seat.
- **A customer's case** (`--customer-case`) takes API keys only: every
  subscription login is refused (`openai-codex/*` whatever the store says),
  as are `--allow-oauth-in-vm` and `--policy ctf`, and each provider's key
  has its owner named (`--key-owner [PROVIDER=]OWNER`: the customer's own,
  or the operator's business account with the customer told). The record
  (`credentials`, per seat) and custody (the anchor, then `models.credentials`
  and a line of the verdict) keep whose key each seat used.

Not done here: deriving a customer's case from the case policy (no preset
says "customer" today, and a test run must not become one by accident), the
DPA reference and retention timer the review proposes beside it, and any
check that an owner named is the key's real holder: the record says what the
operator stated.
