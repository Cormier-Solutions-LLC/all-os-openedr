FROM archlinux:base-devel@sha256:949ecb1661609ab7e8f6854ba03efd62792e7a796313738e94b040c095c20d91 AS builder
RUN pacman-key --init && pacman -Syu --noconfirm --needed python systemd && useradd -m openedr-builder
WORKDIR /source
COPY . .

FROM builder AS check
RUN sh scripts/check-arch.sh

FROM check AS package
ARG RELEASE_VERSION
RUN install -d -o openedr-builder /output && \
    runuser -u openedr-builder -- sh packaging/arch/build.sh "$RELEASE_VERSION" /output

FROM scratch AS artifacts
COPY --from=package /output/ /
