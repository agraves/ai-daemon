#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Show what the verification found when this image was built.
#
# The run itself happened during the build (see the Dockerfile for why it has
# to), so this box is a record rather than a rehearsal. Pass a command to get a
# shell in it instead.
set -eu
if [ "$#" -gt 0 ]; then
  exec "$@"
fi
exec cat /verification.txt
