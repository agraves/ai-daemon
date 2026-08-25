# The Linux test box for /dev/ai development.
#
# Base: official archlinux:latest. Omarchy has no official container image —
# it is an Arch derivative aimed at desktops (Hyprland and all), and the only
# images wearing its name on Docker Hub are third-party uploads with zero
# stars, which is exactly the "somebody else's moving tag" this project's
# daemon refuses on principle. Arch is omarchy's own base, so this is the
# same ground without the borrowed trust.
#
# What it is: a shell you can `docker exec` into, with Claude Code resident
# as the LLM agent — the environment aid's device tree will eventually be
# developed and exercised in.
# Platform pinned because the official archlinux image publishes amd64 only:
# on an Apple Silicon Mac this runs under Rosetta emulation, and on the Linux
# host /dev/ai actually targets it runs native. Pinned here rather than in a
# build flag so the daemon's plain `docker build` gets it right.
FROM --platform=linux/amd64 archlinux:latest

# pacman's own download sandbox (landlock/seccomp) does not survive Docker's
# seccomp profile under emulation — the container is the sandbox here.
RUN sed -i 's/^#\?DisableSandbox.*/DisableSandbox/' /etc/pacman.conf \
 && printf 'DisableSandbox\n' >> /etc/pacman.conf \
 && pacman -Syu --noconfirm nodejs npm git openssh which ripgrep \
 && pacman -Scc --noconfirm

# The CLI ships a platform-native binary via an npm postinstall that global
# root installs skip; run it explicitly so `claude` actually exists.
RUN npm install -g @anthropic-ai/claude-code \
 && node "$(npm root -g)/@anthropic-ai/claude-code/install.cjs" \
 && claude --version

# What this image can be trusted with, published at build time. The daemon
# grants a capability only where it is declared in workflows.yaml AND
# published here AND implemented — a label is a claim, not a grant.
LABEL com.agraves.paperclipper.capabilities="read-source,run-tests"

WORKDIR /workspace
COPY linux-test/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
CMD ["agent"]
