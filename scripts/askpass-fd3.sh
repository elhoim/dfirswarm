#!/bin/sh
# The SSH_ASKPASS helper the signing paths use (scripts/secret-io.ts).
#
# ssh-keygen runs it, with SSH_ASKPASS_REQUIRE=force, whenever it wants a
# key's passphrase or a FIDO authenticator's PIN. The secret is never in this
# script's argv or environment: the process that started ssh-keygen left it
# on an inherited pipe, fd 3, one line per question, and this reads one line
# from there and writes it to stdout, which is the only place ssh-keygen
# reads an answer from. `read` and `printf` are built into the shell, so the
# secret is in no other process's argv either. The prompt ssh-keygen passes
# ($1) is not shown: nobody is looking at this process.
IFS= read -r line <&3 || [ -n "$line" ] || exit 1
printf '%s\n' "$line"
