#!/bin/sh
# Run a command as another user.
#
# A separate program rather than a shell function because the verification
# wraps everything in `timeout`, and `timeout` execs a binary — a function
# named `as` would silently resolve to the GNU assembler instead, which is a
# failure mode worth never having twice.
set -eu
user="$1"
shift
exec setpriv --reuid "$user" --regid "$user" --init-groups --inh-caps=-all -- "$@"
