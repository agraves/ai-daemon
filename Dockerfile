# Build ai-daemon's Arch package, and a box with it installed.
#
# Omarchy is an Arch derivative, so the package format that runs there is
# pacman's: this file goes source -> makepkg -> ai-daemon-*.pkg.tar.zst ->
# `pacman -U`, which is the same path a user on the real distro takes. Nothing
# is copied into place by hand; if the package does not carry a file, the final
# stage does not have it.
#
# Platform pinned for the same reason .foom/agents/linux-test pins it: the
# official archlinux image is amd64-only, so on an Apple Silicon Mac this runs
# emulated and on an x86_64 Linux host it runs native.
FROM --platform=linux/amd64 archlinux:latest AS toolchain

# pacman's own download sandbox does not survive Docker's seccomp profile under
# emulation — the container is the sandbox here.
RUN printf 'DisableSandbox\n' >> /etc/pacman.conf \
 && pacman -Syu --noconfirm base-devel rust git dbus polkit systemd-libs curl sudo \
 && pacman -Scc --noconfirm

# makepkg refuses to run as root, on purpose. Give it somebody to be.
RUN useradd -m -s /bin/bash builder \
 && echo 'builder ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/builder

# ---------------------------------------------------------------------------
# Dependency layer: the crate graph changes far less often than our own code,
# so fetch and compile it against placeholder sources and let Docker cache it.
# ---------------------------------------------------------------------------
FROM toolchain AS deps
USER builder
ENV CARGO_HOME=/home/builder/.cargo CARGO_TARGET_DIR=/home/builder/target
WORKDIR /home/builder/src
COPY --chown=builder Cargo.toml ./
COPY --chown=builder crates/ai-daemon-proto/Cargo.toml crates/ai-daemon-proto/
COPY --chown=builder crates/ai-daemon/Cargo.toml crates/ai-daemon/
COPY --chown=builder crates/ai-daemon-backend-mock/Cargo.toml crates/ai-daemon-backend-mock/
COPY --chown=builder crates/ai-daemon-backend-llamacpp/Cargo.toml crates/ai-daemon-backend-llamacpp/
COPY --chown=builder crates/ai-daemon-backend-remote/Cargo.toml crates/ai-daemon-backend-remote/
COPY --chown=builder crates/ai-daemon-portal/Cargo.toml crates/ai-daemon-portal/
COPY --chown=builder crates/ai-run/Cargo.toml crates/ai-run/
COPY --chown=builder crates/ai-daemon-fetch/Cargo.toml crates/ai-daemon-fetch/
COPY --chown=builder crates/ai-daemon-decode/Cargo.toml crates/ai-daemon-decode/
COPY --chown=builder crates/ai-daemon-shim/Cargo.toml crates/ai-daemon-shim/
COPY --chown=builder crates/aidctl/Cargo.toml crates/aidctl/
RUN set -eu; \
    for d in crates/*/; do mkdir -p "$d/src"; done; \
    echo 'pub fn placeholder() {}' > crates/ai-daemon-proto/src/lib.rs; \
    for c in ai-daemon ai-daemon-backend-mock ai-daemon-backend-llamacpp ai-daemon-backend-remote \
             ai-daemon-portal ai-run \
             ai-daemon-fetch ai-daemon-decode ai-daemon-shim aidctl; do \
        echo 'fn main() {}' > "crates/$c/src/main.rs"; \
    done; \
    cargo build --release --workspace; \
    cargo generate-lockfile --offline || true

# ---------------------------------------------------------------------------
# Compile the workspace from source. Separate from the package build so a
# compile error shows up as a compile error rather than as makepkg noise.
# ---------------------------------------------------------------------------
FROM deps AS build
USER builder
ENV CARGO_HOME=/home/builder/.cargo CARGO_TARGET_DIR=/home/builder/target
WORKDIR /home/builder/src
COPY --chown=builder . /home/builder/src
# Docker preserves source mtimes, and the placeholder sources compiled in the
# deps layer were written later than the real ones. Without this, cargo sees a
# newer artifact than input and happily links the placeholders.
RUN find crates -name *.rs -newermt @0 -exec touch {} +
# Licence gate: every source file carries an SPDX header, checked rather than
# hoped. The workspace is Apache-2.0 and Cargo.toml says so once for every
# crate; the per-file line is for the person reading one file out of context —
# a promise that rots the first time a header is forgotten, unless forgetting
# it fails the build.
RUN missing=$(grep -rL "SPDX-License-Identifier:" --include="*.rs" crates; \
      grep -L "SPDX-License-Identifier:" examples/think.py \
        packaging/verify/*.sh packaging/verify/*.rs packaging/arch/make-package.sh); \
    if [ -n "$missing" ]; then \
      echo "missing an SPDX header:"; echo "$missing"; exit 1; fi
# Lint gate. The tests run in the package build, where makepkg's check()
# runs them — the same place a distro would run them, rather than only here.
RUN cargo build --release --workspace \
 && cargo clippy --release --workspace --all-targets -- -D warnings

# ---------------------------------------------------------------------------
# The package. makepkg, from a source tarball, exactly as a user building from
# a PKGBUILD would — no shortcut that produces an artifact only this Dockerfile
# knows how to make.
# ---------------------------------------------------------------------------
# Built on top of the lint stage, so a clippy failure stops the package rather
# than shipping past it. makepkg compiles again under its own flags and runs
# check() — that duplication is the point: the package is built the way a user
# building it would, not the way this Dockerfile found convenient.
FROM build AS package
USER builder
WORKDIR /home/builder/src
RUN ./packaging/arch/make-package.sh
RUN ls -l packaging/arch/*.pkg.tar.zst

# ---------------------------------------------------------------------------
# Does it still compile for arm64?
#
# This exists because the answer was no and nothing noticed. The seccomp filter
# in ai-daemon-decode is written for both architectures — per-arch AUDIT_ARCH
# constants, the whole module cfg-gated on the pair — but it named SYS_poll,
# which arm64 has no syscall for and the libc crate therefore does not define,
# so the crate did not build there at all. The shipped package is x86_64, so no
# build in this repository ever asked.
#
# Native here rather than emulated: this host is arm64, and it is the amd64
# stages above that pay for translation. Pinned to the exact toolchain the
# workspace claims as its minimum, so rust-version is checked by being used
# rather than by being asserted.
FROM --platform=linux/arm64 rust:1.87-slim AS aarch64-check
WORKDIR /src
COPY . /src
RUN cargo check --workspace --locked --all-targets && touch /src/arch-ok

# ---------------------------------------------------------------------------
# A box with the package installed, and nothing of the build tree in it.
# Everything the verification touches came out of pacman.
# ---------------------------------------------------------------------------
FROM --platform=linux/amd64 archlinux:latest AS box
# Two departures from the image's stock pacman.conf. The container image ships
# `NoExtract = usr/share/doc/*`, so a package's docs are listed by the database
# and absent from the disk; a real install extracts them and the verification
# reads them (it runs the packaged example), and a box that silently differed
# from a real machine here cost an afternoon — pacman -Ql swore the file
# existed while python could not open it.
#
# python-gobject and python-cbor2 are not the daemon's dependencies. They are
# examples/think.py's, and the verification runs it because an example that
# rots is worse than none.
RUN printf 'DisableSandbox\n' >> /etc/pacman.conf \
 && sed -i '/^NoExtract.*usr\/share\/doc/d' /etc/pacman.conf \
 && pacman -Syu --noconfirm dbus polkit systemd curl iproute2 rust \
      python-gobject python-cbor2 \
 && pacman -Scc --noconfirm

# Pulls the arm64 stage into the graph, so a build that does not compile there
# is a build that fails here.
COPY --from=aarch64-check /src/arch-ok /var/lib/ai-daemon-arch-ok
COPY --from=package /home/builder/src/packaging/arch/*.pkg.tar.zst /tmp/
RUN pacman -U --noconfirm /tmp/ai-daemon-*.pkg.tar.zst && rm -f /tmp/*.pkg.tar.zst

# sysusers.d ran as part of the install; prove it did rather than assuming.
RUN getent passwd ai-daemon && getent group ai

# The verification's own fixtures. Compiled here, not packaged: a PNG writer is
# a test tool, and shipping one in the daemon's package would be shipping a
# thing nobody asked for.
COPY packaging/verify/make-png.rs /tmp/make-png.rs
# And a stand-in for somebody else's inference service, so the remote provider
# has something to be remote *to*. Nothing in this build has a network, and a
# test that spends money on a real endpoint is not a test.
COPY packaging/verify/stub-endpoint.rs /tmp/stub-endpoint.rs
RUN rustc -O -o /usr/local/bin/make-png /tmp/make-png.rs && rm /tmp/make-png.rs \
 && rustc -O -o /usr/local/bin/stub-endpoint /tmp/stub-endpoint.rs && rm /tmp/stub-endpoint.rs \
 && pacman -Rns --noconfirm rust && pacman -Scc --noconfirm

COPY packaging/verify/run.sh /usr/local/bin/verify
COPY packaging/verify/boot.sh /usr/local/bin/boot
COPY packaging/verify/report.sh /usr/local/bin/report
COPY packaging/verify/runas.sh /usr/local/bin/runas
RUN chmod +x /usr/local/bin/verify /usr/local/bin/boot /usr/local/bin/report /usr/local/bin/runas

# The verification runs *here*, during the build, and not at container start.
#
# That is forced rather than chosen: this project owns `dev run`, which starts
# containers with every capability dropped, and the run needs CAP_SETUID to act
# as three different users, CAP_DAC_OVERRIDE for the model store, and a dbus
# and polkit that can drop to their own users. A build step has those. Making
# the run weaker to fit the runner would have meant deleting the identity tests,
# which are the ones worth having.
#
# The consequence is that a failing verification fails the build — which is the
# right way round — and a passing one leaves its transcript in the image.
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# The outer stop: if the whole run wedges, the build fails in twenty minutes
# with a transcript that ends where it stuck, rather than never finishing.
RUN timeout 1200 /usr/local/bin/boot 2>&1 | tee /verification.txt

# Default to printing what happened, so `dev run … && dev logs` shows the
# report. Any other command runs as given.
ENTRYPOINT ["/usr/local/bin/report"]
