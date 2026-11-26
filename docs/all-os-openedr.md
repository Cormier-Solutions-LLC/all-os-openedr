# All OS OpenEDR preview

This software is subject to the terms of the Comodo Available Source License Agreement. See [the license](../LICENSE.md) and [redistribution notices](../NOTICE.md). Downstream distributions are free. Git history identifies the upstream code and downstream changes.

## Debian 13

Use the versioned `all-os-openedr_<version>_all.deb` asset from the [GitHub releases](https://github.com/Cormier-Solutions-LLC/all-os-openedr/releases). From the source checkout, build it with `sh packaging/debian/build.sh "$(cat VERSION)" ./dist` on Debian.

```sh
version='<downloaded-version>'
sudo apt install "./all-os-openedr_${version}_all.deb"
sudo systemctl enable --now all-os-openedr.service
sudo systemctl status all-os-openedr.service
sudo head -n 1 /var/log/all-os-openedr/events.jsonl
```

The service runs as a dynamic, unprivileged user without network access. It emits process observations visible through procfs. Short-lived processes can be missed between polls. A restart may emit observations again, with the same event ID for processes that are still running. The preview collects names and PIDs. Command lines, environment values and file content are outside this event contract. Before leaving the preview active, configure and test rotation and retention with the Wazuh log collector in your environment. The collector reopens the output on each nonempty poll, so it follows a new file after rotation.

### Kernel process lifecycle

On a Debian host with the Linux process connector enabled, start the optional lifecycle service. It consumes kernel fork, successful exec, and task exit notifications, including processes that finish between polling samples. It runs without capabilities and uses a separate log path. Use the service in the host namespaces. Events from nested PID namespaces use host PID and thread ID values. [Linux process connector interface](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/cn_proc.h)

```sh
sudo systemctl enable --now all-os-openedr-lifecycle.service
sudo systemctl status all-os-openedr-lifecycle.service
sudo head -n 1 /var/log/all-os-openedr-lifecycle/events.jsonl
```

Fork events carry the parent PID and thread ID, and link to the parent's process identity when its birth was observed. The collector keeps that identity while observed members of the thread group remain alive. Task exits record the raw Linux wait status and distinguish leader exits from worker-thread exits. Use the separate Audit collector for executable path evidence.

Each service start emits a new stream ID. Running processes whose births predate the stream can still emit lifecycle events with host PIDs. Their earlier process identities are unavailable in the new stream. Kernel event IDs incorporate boot ID, CPU, kernel sequence, and monotonic time. When the collector detects loss, it emits `process.stream_gap` and discards prior lineage so subsequent records do not inherit uncertain process identities. Review stream gaps before using the events for a complete timeline.

Merge the packaged `lifecycle-localfile.xml` into the Wazuh agent and install the packaged `110100-openedr_rules.xml` in the manager's local rules directory. Confirm rule IDs 110100 through 110103 are available. Rule 110102 covers lifecycle events and rule 110103 reports loss of continuity. The lifecycle stream can grow quickly on busy hosts. Configure rotation and retention for this separate path and verify that the Wazuh agent follows the new file after rotation.

### Kernel execution detection with Wazuh

On Debian 13 amd64, Linux Audit can detect a successful launch of a protected executable by a login identity other than the one you approve. Choose a real executable stored under an administrator-controlled path and use the numeric UID of the approved login account. Audit records the original login UID across privilege changes. The policy excludes processes whose login UID is unset, including many system services.

```sh
sudo apt install auditd
all-os-openedr-audit-rules \
    --protected-executable /usr/local/libexec/protected-tool \
    --approved-login-uid 1000 > openedr-execution.rules
cat openedr-execution.rules
sudo install -m 0600 openedr-execution.rules /etc/audit/rules.d/40-openedr-execution.rules
sudo augenrules --load
sudo auditctl -l
sudo auditctl -s
```

Replace the example path and login UID with your policy values. The command only prints rules, so review them before installation. Audit uses the first matching rule. Reconcile these rules with your existing audit configuration, including any earlier suppress rules, broad execution rules, or immutable policy. If the protected executable is replaced or moved, verify the watches against the new executable. To also collect successful executions from logged-in accounts at or above a given UID, pass `--observe-login-execs-from UID`. That option can generate substantial event volume. Monitor the Audit `lost` counter. Audit can record command-line arguments, so restrict access and set retention for both Audit logs and Wazuh data.

On the enrolled endpoint, merge the packaged `/usr/share/all-os-openedr/wazuh/audit-localfile.xml` into the Wazuh agent configuration if the agent does not already collect `/var/log/audit/audit.log` with the `audit` format. On the manager, install the packaged `110110-openedr-execution_rules.xml` in its local rules directory, confirm rule IDs 110110 through 110113 are available, and validate the manager configuration. Restart the agent and manager after changing their respective configurations. An unexpected login UID launching the protected executable raises rule 110110. Optional session execution events use rule 110111. AppArmor execution denials raise rule 110112. Denied file mutations under an OpenEDR AppArmor profile raise rule 110113. Both AppArmor rules retain the original audit record as evidence.

### Pre-execution control for a managed workload

On a Debian 13 endpoint with AppArmor enabled, start a systemd service through `aa-exec --immediate` under a dedicated unprivileged user. The kernel checks the service and its descendants against the loaded allowlist before each executable launch, including while the management backend is unavailable. Enforcement applies within the assigned service context. Profile creation and attachment are explicit administrator actions.

Install `apparmor` and review the profile before loading it. The example uses a statically linked executable. Pass `--allow-library PATH` for each trusted library needed by a dynamically linked workload and `--read-file PATH` for needed input files. Pass `--write-file PATH` for individual existing output files. Use administrator-controlled directories for all approved code and avoid allowing generic interpreters or tools that can execute user-provided code. Use a separate profile and isolated VM for analysis of unknown candidates.

The profile restricts writes to the default journald socket. This example sends workload output to a dedicated file. Replace `workload-user` with the service account and its group in the examples. Linux Audit continues to record kernel denials separately.

```sh
sudo install -d -o root -g workload-user -m 0750 /var/log/all-os-openedr-managed
sudo touch /var/log/all-os-openedr-managed/workload.log
sudo chown root:workload-user /var/log/all-os-openedr-managed/workload.log
sudo chmod 0660 /var/log/all-os-openedr-managed/workload.log
sudo all-os-openedr-apparmor-policy --name workload \
    --allow-executable /usr/local/libexec/workload \
    --write-file /var/log/all-os-openedr-managed/workload.log > all-os-openedr-workload
sudo apparmor_parser -Q -K ./all-os-openedr-workload
sudo install -o root -g root -m 0644 ./all-os-openedr-workload /etc/apparmor.d/
sudo apparmor_parser -a -K /etc/apparmor.d/all-os-openedr-workload
sudo grep -Fx 'all-os-openedr-workload (enforce)' /sys/kernel/security/apparmor/profiles
```

Use canonical paths in the unit and add the following as a drop-in through `systemctl edit`. Preserve your service's approved arguments. Set `PrivateNetwork=yes` for workloads that require no network. The `--immediate` option enters the profile before the first executable is evaluated. A missing profile stops the service from launching the workload.

```ini
[Service]
User=workload-user
Group=workload-user
NoNewPrivileges=yes
StandardOutput=append:/var/log/all-os-openedr-managed/workload.log
StandardError=inherit
ExecStart=
ExecStart=/usr/bin/aa-exec --immediate --profile all-os-openedr-workload -- /usr/local/libexec/workload
```

Restart the service and verify a permitted launch, a denied launch, and graceful shutdown. The profile permits standard lifecycle signals from an unconfined service manager and permits normal signalling between processes in the same profile. Use a separate profile name for each workload. Stage updates outside `/etc/apparmor.d`, validate them with `apparmor_parser -Q -K`, and retain the last working profile outside that directory. To apply an update or roll it back, reload the chosen profile with `apparmor_parser -r -K PATH`, install the same file into its persistent location, and restart and retest the affected service. If loading or persistence fails, restore the last working profile in the kernel and on disk before restarting. The package leaves profile lifecycle under administrator control.

### Protect local directories and mounted SMB shares

Pass `--protect-tree DIR` to grant recursive reads and have AppArmor block and audit writes, appends, and hard links through the protected paths. Pass `--write-directory DIR` to allow creation, updates, and renames of files directly under a separate existing directory. The writable rule leaves subdirectories outside its scope. AppArmor matches canonical paths and applies the profile to the managed workload and its descendants. [Debian AppArmor policy syntax](https://manpages.debian.org/trixie/apparmor/apparmor.d.5.en.html)

Add these arguments to the profile generation command for a workload that reads an archive and writes an outbox on the same mounted share.

```sh
    --protect-tree /srv/smb/archive \
    --write-directory /srv/smb/outbox
```

In the systemd drop-in, require the share before starting the workload.

```ini
[Unit]
RequiresMountsFor=/srv/smb
AssertPathIsMountPoint=/srv/smb
```

Keep writable directories and files distinct from protected data at the storage layer. Check for alternate exports, bind mounts, and hard links that expose the same data through write-approved paths. Enforce server-side access controls for clients and processes outside the OpenEDR profile. Verify the workload's allowed outputs and blocked mutations against a disposable share before applying the policy to live data.

### Enforce writer authorization on a Samba server

On a standalone Samba server running Debian 13, configure separate Unix reader and writer groups and give authenticated Samba accounts only the membership they need. Samba checks writer-group membership on the server, so onboarding the SMB client to OpenEDR is optional for this control. The backing filesystem must also grant writes to approved identities. Keep the protected data out of any other export that grants broader writes.

Install `samba`, `samba-vfs-modules`, and `rsyslog` on the server. Render a new dedicated share using an existing directory and groups.

```sh
all-os-openedr-samba-policy \
    --share protected-archive --directory /srv/samba/protected-archive \
    --readers-group archive-readers --writers-group archive-writers > protected-archive.conf
```

Review the section, install it as a root-owned fragment under `/etc/samba/`, and add `include = /etc/samba/protected-archive.conf` to the base Samba configuration. Use an unused share name and review the full effective configuration with `testparm -s` before loading it. This share requires SMB encryption and uses the `full_audit` VFS module. For updates or rollback, validate the replacement configuration and ensure clients reconnect to the share. Existing SMB connections can retain the permissions in effect when they connected. [Samba share configuration](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html)

Install `/usr/share/all-os-openedr/samba/rsyslog.conf` as a root-owned file under `/etc/rsyslog.d/`, validate with `rsyslogd -N1`, and reload the service. Merge the packaged `samba-localfile.xml` into the Wazuh agent on the Samba server. On the Wazuh manager, install `openedr-samba_decoders.xml` in the local decoders directory and `110114-openedr-samba_rules.xml` in the local rules directory. These files are under `/usr/share/all-os-openedr/wazuh/`. Confirm rule IDs 110114 through 110117 are available, validate the configuration, and restart the affected Wazuh components.

Rsyslog routes the share's original VFS audit payloads under the dedicated `openedr_smb_audit` tag. Wazuh alerts on failed file mutation calls and failed opens that requested mutation access. It retains the captured operation, share, account, client address, and audit line. The VFS log reports operation failures and their intent. It can differ from the SMB status returned to the client, so use client or server protocol evidence when an exact denial reason matters. Protect access to these logs and apply the retention policy for your environment. [Samba full-audit format](https://manpages.debian.org/trixie/samba/vfs_full_audit.8.en.html)

The [Debian EDR milestone](https://github.com/Cormier-Solutions-LLC/all-os-openedr/milestone/14) tracks Windows feature parity, including process lifetime and lineage, prevention, containment, and recovery.

## Enterprise Linux and Fedora RPM preview

Build the RPM inside a target release using a checkout or the versioned preview source archive. Install the build requirements and create a versioned RPM for that host.

```sh
sudo dnf install rpm-build systemd-rpm-macros tar gzip
sh packaging/rpm/build.sh "$(cat VERSION)" ./dist
sudo dnf install ./dist/all-os-openedr-*.rpm
sudo systemctl enable --now all-os-openedr.service
```

Build into an empty directory for each target so the install command selects one RPM. The build uses Python 3.11 on Enterprise Linux 9 and the system Python on Enterprise Linux 10 and Fedora. The systemd preset keeps the service disabled until an operator enables it. The RPM installs the CASL license and redistribution notice under `/usr/share/licenses/all-os-openedr`.

Rocky Linux 9 and 10 and Fedora 44 passed container build, install, upgrade, one-shot event generation, and removal checks. Run `scripts/check-rpm.sh` as root in a disposable target container to repeat those checks. Host systemd startup, SELinux enforcing behavior, Wazuh alert delivery, and the wider distribution matrix remain qualification items.

## Arch Linux package

Download the versioned `all-os-openedr-<version>-1-any.pkg.tar.zst` and corresponding `SHA256SUMS-<version>.txt` from [GitHub Releases](https://github.com/Cormier-Solutions-LLC/all-os-openedr/releases). In the download directory, set `version` to the download's full release version and verify the package before installing it.

```sh
version=0.5.0
package="all-os-openedr-$version-1-any.pkg.tar.zst"
awk -v name="./$package" '$2 == name' "SHA256SUMS-$version.txt" | sha256sum --check &&
    sudo pacman -U "./$package"
```

Enable the service once the package installs.

```sh
sudo systemctl enable --now all-os-openedr.service
```

On a build host with `base-devel`, `python`, and `systemd` installed, run `sh packaging/arch/build.sh "$(cat VERSION)" ./dist` as a regular user. The nightly filename contains the complete release identifier. Pacman uses a normalized metadata version so that the corresponding stable release sorts after it.

Run `sudo systemctl restart all-os-openedr.service` after an upgrade to load the new code. `sudo pacman -R all-os-openedr` stops the service and clears its enablement while retaining the event log. The package installs `LICENSE.md` and `NOTICE.md` under `/usr/share/licenses/all-os-openedr/`.

## Alpine APK and OpenRC

Install `alpine-sdk`, `openrc`, and `python3` on the Alpine build host. Configure `abuild` as an unprivileged builder with an operator-controlled package signing key. For a new local builder, `abuild-keygen -a -n` creates a key and configures `abuild` to use it. Install only the corresponding public key in `/etc/apk/keys/` on the trusted builder and target. Verify the public key with its owner before importing it.

```sh
sh packaging/alpine/build.sh "$(cat VERSION)" ./dist
```

Copy the signed APK to the target and install it as root. Replace `VERSION` in the filename with the build's numeric version.

```sh
apk add ./all-os-openedr-VERSION-r0.apk
rc-service all-os-openedr start
rc-update add all-os-openedr default
```

The service is opt-in, including at boot. After a package upgrade, run `rc-service all-os-openedr restart` to load the new code. Removing the package stops the service and removes its runlevel entries while retaining the event log and service account. The package includes `LICENSE.md` and `NOTICE.md` in `/usr/share/licenses/all-os-openedr/`.

Alpine 3.23.8 and 3.24.4 passed signed APK install, upgrade, OpenRC start and restart, and removal in x86_64 containers. The service ran with no effective capabilities and wrote JSON lines to `/var/log/all-os-openedr/events.jsonl` with mode `0640`. A Wazuh 4.14.11 manager received an Alpine-generated event through a read-only shared log directory and matched rule 110101. On a shared filesystem, expose the log directory read-only to a supported Wazuh log reader and apply the JSON collection stanza below. Wazuh's [package list](https://documentation.wazuh.com/current/installation-guide/packages-list.html) currently provides DEB and RPM builds for Linux.

## Direct Wazuh ingestion and Wazah OpenSearch

1. Add [the JSON localfile stanza](../integrations/wazuh/localfile.xml) to the Wazuh agent's existing `ossec_config`. Use an endpoint with an enrolled Wazuh agent and verify that the logcollector can read the protected file.
2. Reserve Wazuh local rule IDs 110100 and 110101 and install [the rules](../integrations/wazuh/110100-openedr_rules.xml) under `/var/ossec/etc/rules/` on the manager. Test the [fixture](../integrations/wazuh/process-observed.json) with `/var/ossec/bin/wazuh-logtest`. It should match 110101 at level 3. Adjust collection and severity to the site's alert volume before rolling out broadly.
3. Validate the Wazuh configuration and restart the services during the approved test window. Confirm a benign endpoint observation in the manager's `alerts.json`.
4. In a Wazuh-managed indexer such as Wazah's deployment, first verify the existing Filebeat stream by finding the alert in `wazuh-alerts-4.x-*`. If the management API reads those shared indices, set its prefix to `wazuh-alerts-4.x` and grant a read-only role with document-level security scoped to the OpenEDR source.
5. For a separate destination or dedicated indices on the existing OpenSearch cluster, follow the dedicated-index setup below.

References for supported topology and syntax are the [Wazuh OpenSearch integration](https://documentation.wazuh.com/current/integrations-guide/opensearch/index.html) and [Wazuh rule testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html). The sample uses the Linux preview's normalized schema. The [upstream Windows guide](../getting-started/SettingFileBeat.md) describes log collection from `C:\ProgramData\edrsvc\log\*`. Capture representative logs on a licensed Windows test endpoint before implementing its normalization adapter.

### Dedicated OpenSearch indices

Apply the following request bodies with a cluster operator identity. Map the roles to separate operator-managed identities. Use the writer only for Logstash and the reader only for alert search.

| API request | Body |
| --- | --- |
| `PUT /_index_template/openedr-alerts-v1` | [Index template](../integrations/wazuh/openedr-index-template.json) |
| `PUT /_plugins/_security/api/roles/openedr_v1_writer` | [Writer role](../integrations/wazuh/openedr-writer-role.json) |
| `PUT /_plugins/_security/api/roles/openedr_v1_reader` | [Reader role](../integrations/wazuh/openedr-reader-role.json) |
| `PUT /_plugins/_ism/policies/openedr-alert-retention-v1` | [Optional 30-day retention policy](../integrations/wazuh/openedr-retention-policy.json) |

The optional policy attaches to new dedicated indices and deletes them by index age. Choose the retention interval with the cluster owner before applying it. The index template maps the preview fields explicitly and leaves extra fields out of the mappings.

Install the [Logstash pipeline](../integrations/wazuh/openedr-opensearch.conf) on a host with read-only access to the manager's `alerts.json`. Merge the entry from [openedr-pipelines.yml](../integrations/wazuh/openedr-pipelines.yml) into the host's pipeline settings. Persist Logstash's data directory and the separate `OPENEDR_SINCEDB_PATH` position file. Supply `OPENEDR_OPENSEARCH_URL`, the approved CA at `OPENEDR_OPENSEARCH_CA_FILE`, and `OPENEDR_OPENSEARCH_USERNAME` and `OPENEDR_OPENSEARCH_PASSWORD` from the Logstash keystore. Size the persistent queue and upstream alert retention for the length of outage the site needs to tolerate.

Validate the configuration, generate a benign observation, and query the dedicated index as the reader for its `data.openedr_event_id`. The UTC observation date determines the index and the event ID determines the document key, so an identical alert replay updates the same document. An observation emitted again with a new UTC date can appear in another daily index. Check that the writer receives 403 outside the dedicated index pattern before enabling the route.

For rollback, stop the dedicated forwarder and preserve its queue and position file. Restore the prior pipeline and manager rule configuration, then remove the endpoint stanza from the affected Wazuh agents and validate their configuration. A cluster operator can detach the optional retention policy when preserving the indexed records is required. Keep the existing Wazuh alert route in place during the change.

An isolated lab used Wazuh agent, manager, and indexer 4.14.11 with Logstash OSS 8.19.23 and OpenSearch output plugin 2.1.1. It verified duplicate handling, endpoint log rotation, the dedicated roles, and retention policy attachment. Twelve synthetic alerts queued during an indexer outage were indexed once each after a forced Logstash restart and indexer recovery. The production Wazah rollout and scheduled retention expiry remain to be verified.

## Kubernetes management preview

The stateless API serves recent OpenEDR alert fields from the dedicated OpenSearch index. The chart uses a private ClusterIP service, a disruption budget and multi-node scheduling. Use Kubernetes 1.30 or later with topology-spread node inclusion policies enabled. Keep at least two eligible worker nodes and enough allocatable capacity for a surge replica during an upgrade. Nodes with untolerated taints are excluded from the spread calculation. Before sending a bearer token across the network, use port forwarding for local testing or place a TLS-authenticating proxy in front of the service and apply your network policies.

Build `deploy/manager.Dockerfile` and make the resulting image available in your cluster's registry. Use a digest reference in the deployment. Create Kubernetes Secrets with the keys listed in [values.yaml](../deploy/chart/values.yaml), then supply a site-local values file to Helm.

```sh
helm upgrade --install openedr ./deploy/chart --namespace openedr --create-namespace \
  -f /path/to/site-values.yaml --wait --timeout 5m
```

`/healthz` checks the process, `/readyz` checks OpenSearch query access, and `/v1/events` requires the management bearer token. During an indexer outage, the manager remains live and withdraws from the Service until readiness recovers. The preview provides read access to telemetry.

Qualification used a local Kubernetes 1.35.8 cluster with three workers and a TLS fixture. The manager served authenticated traffic during a rolling upgrade, pod replacement, and a planned worker drain. After the drain, the remaining two workers carried all three replicas. Rehearse these operations against your site topology and capacity before enabling live traffic.

## Plugin contract

Agent plugins declare a name, API version, role and factory. Collectors provide `poll()` and return normalized event dictionaries. Sinks implement `write(events)`. Select the built-in plugins with `--collector linux-processes` and `--sink json-lines`.

An operator can install a trusted Python distribution into the service's environment and select an entry point explicitly as `distribution:plugin-name`. Use the `all_os_openedr.plugins` entry point group and export a `Plugin` object from `all_os_openedr.plugins` with API version 1 and the role `collector` or `sink`. Plugins run in the agent process with its permissions. The agent loads only explicitly selected entry points.

## macOS

Run `sh packaging/macos/install.sh` for the installer stub. The native plan covers Apple silicon and Intel, the Endpoint Security entitlement, signed system extensions, notarization, and real-device install and removal tests.

## GitHub delivery

The project moves work from Backlog to Open, In Process, Pending Merge, Merged, and Released. Move an issue to Released when the published version contains it and the target's delivery checks pass. Daily upstream reconciliation imports clean changes from the corresponding upstream branch. A conflict, rewritten upstream history, or changes to licensing or workflow files requires maintainer review.

GitHub's repository Actions policy restricts workflow execution to the maintainer and permits only `push`, `pull_request_target`, `schedule`, and `workflow_dispatch`. Keep that policy active before enabling Actions. Maintainer updates and same-repository maintainer PRs from protected `codex/` or `release/` branches use `cormier-runners`. The PR workflow uses the base branch definition and checks out the exact head SHA after its identity checks pass. Contributors can run `sh scripts/check-preview.sh` in a local Linux environment and submit changes from their own forks. Keep the maintainer-only branch and stable tag rulesets active. Use Codex review on the exact PR revision before merging or publishing a stable release.

For stable publication, open the maintainer release PR against main. Verify the Codex summary reports a completed code review with no unresolved findings on the final PR head. Merge while the PR head and resulting release commit have the same tree. Update the maintainer branch `release/<version>` to that release commit, push the matching `v<version>` tag, and dispatch `Preview CI and release` on that branch with the stable channel.
