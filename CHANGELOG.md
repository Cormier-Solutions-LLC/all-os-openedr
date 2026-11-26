# Changelog

## 0.6.0 preview

- Add opt-in AppArmor execution allowlists for Debian 13 managed workloads. The kernel enforces the allowlist offline, and Wazuh can alert when the workload is denied an executable.
- Add opt-in Debian 13 amd64 kernel Audit policy for protected-executable detection. An enrolled Wazuh agent can send the kernel event to a manager rule for operator investigation.
- Provide optional Audit rules for successful login-session executions, including processes that exit between polling samples.

## 0.5.0

- Publish versioned Arch Linux packages with pacman support for upgrading from nightly to stable.
- Reuse the hardened systemd service, leave startup opt-in, and retain event logs on package removal.

## 0.4.0

- Add a locally signed Alpine APK source build with a supervised, opt-in OpenRC service that runs as an unprivileged account.

## 0.3.0

- Add dedicated OpenSearch mappings, narrowly scoped forwarding and search roles, and an example retention policy.
- Route identical Wazuh alert replays by their original observation date and event ID. Provide a bounded persistent queue for interruption recovery.
- Verify the dedicated index route in a disposable Wazuh 4.14.11 lab, including restart recovery, restricted roles, and retention policy attachment.
- Run maintainer PR checks from the protected base workflow under the public fork's maintainer-only Actions policy.

## 0.2.0

- Add RPM source builds for Enterprise Linux and Fedora, with container checks for Rocky Linux 9 and 10 and Fedora 44.
- Require the maintainer identity again when a publication job is retried.
- Exclude nodes with untolerated taints from Helm scheduling calculations so a rollout can place its surge replica.
- Verify the Debian 13 systemd package lifecycle on amd64 and arm64.

## 0.1.0

- Add a Debian 13 package for unprivileged Linux process telemetry.
- Add a versioned plugin registry with explicit selection of locally installed plugins.
- Add direct Wazuh JSON ingestion, a Wazah OpenSearch routing guide, and a dedicated-index forwarding example.
- Add the read-only management container and a multi-replica Helm chart.
- Add the macOS installer stub and publish versioned preview artifacts with checksums and license notices.

Debian 13 container package checks, Wazuh rule tests, management API smoke tests, and a Kubernetes server-side dry run were used to qualify this preview. The project tracks systemd host and multi-architecture tests, live alert delivery, Kubernetes failover, and broader platform coverage.
