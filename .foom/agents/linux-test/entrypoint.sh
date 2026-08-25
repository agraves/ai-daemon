#!/bin/sh
# linux-test: a live Linux box with an agent in residence.
#
#   agent (default)  keep the box up. Chat turns arrive as
#                    `docker exec … claude --print`, shell commands as
#                    `docker exec … sh -c '…'` — the box itself just stays.
#   <anything else>  run it and exit, so the image doubles as a one-shot
#                    command runner.
set -e

case "${1:-agent}" in
  agent)
    echo "[linux-test] up — exec in for a shell, chat for the agent"
    exec tail -f /dev/null
    ;;
  *)
    exec "$@"
    ;;
esac
