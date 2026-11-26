# Changelog

## Unreleased

- Add RPM source builds for Enterprise Linux and Fedora, with container checks for Rocky Linux 9 and 10 and Fedora 44.
- Require the maintainer identity again when a publication job is retried.

## 0.1.0

- Add a Debian 13 package for unprivileged Linux process telemetry.
- Add a versioned plugin registry with explicit selection of locally installed plugins.
- Add direct Wazuh JSON ingestion, a Wazah OpenSearch routing guide, and a dedicated-index forwarding example.
- Add the read-only management container and a multi-replica Helm chart.
- Add the macOS installer stub and publish versioned preview artifacts with checksums and license notices.

Debian 13 container package checks, Wazuh rule tests, management API smoke tests, and a Kubernetes server-side dry run were used to qualify this preview. The project tracks systemd host and multi-architecture tests, live alert delivery, Kubernetes failover, and broader platform coverage.
