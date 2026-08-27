#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Run a command as another user.
#
# A separate program rather than a shell function because the verification
# wraps everything in `timeout`, and `timeout` execs a binary — a function
# named `as` would silently resolve to the GNU assembler instead, which is a
# failure mode worth never having twice.
set -eu
user="$1"
shift
# Bounded here rather than at each call site. Most invocations go through
# check/refute, which already wrap in a timeout, but the bare ones did not —
# and a hang in one of those has nothing to localise it, so it eats the whole
# run's budget and the transcript just stops.
exec timeout 90 setpriv --reuid "$user" --regid "$user" --init-groups --inh-caps=-all -- "$@"
