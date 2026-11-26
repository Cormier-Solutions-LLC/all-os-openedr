# All OS OpenEDR preview

This software is subject to the terms of the Comodo Available Source License Agreement. See [the license](../LICENSE.md) and [redistribution notices](../NOTICE.md). Downstream distributions are free. Git history identifies the upstream code and downstream changes.

## Debian 13

Use the versioned `all-os-openedr_<version>_all.deb` asset in the private repository's releases. From the source checkout, build it with `sh packaging/debian/build.sh "$(cat VERSION)" ./dist` on Debian.

```sh
sudo apt install ./all-os-openedr_0.2.0_all.deb
sudo systemctl enable --now all-os-openedr.service
sudo systemctl status all-os-openedr.service
sudo head -n 1 /var/log/all-os-openedr/events.jsonl
```

The service runs as a dynamic, unprivileged user without network access. It emits process observations visible through procfs. Short-lived processes can be missed between polls. A restart may emit observations again, with the same event ID for processes that are still running. The preview collects names and PIDs. Command lines, environment values and file content are outside this event contract. Before leaving the preview active, configure and test rotation and retention with the Wazuh log collector in your environment. The collector reopens the output on each nonempty poll, so it follows a new file after rotation.

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

## Direct Wazuh ingestion and Wazah OpenSearch

1. Add [the JSON localfile stanza](../integrations/wazuh/localfile.xml) to the Wazuh agent's existing `ossec_config`. Use an endpoint with an enrolled Wazuh agent and verify that the logcollector can read the protected file.
2. Reserve Wazuh local rule IDs 110100 and 110101 and install [the rules](../integrations/wazuh/110100-openedr_rules.xml) under `/var/ossec/etc/rules/` on the manager. Test the [fixture](../integrations/wazuh/process-observed.json) with `/var/ossec/bin/wazuh-logtest`. It should match 110101 at level 3. Adjust collection and severity to the site's alert volume before rolling out broadly.
3. Validate the Wazuh configuration and restart the services during the approved test window. Confirm a benign endpoint observation in the manager's `alerts.json`.
4. In a Wazuh-managed indexer such as Wazah's deployment, first verify the existing Filebeat stream by finding the alert in `wazuh-alerts-4.x-*`. If the management API reads those shared indices, set its prefix to `wazuh-alerts-4.x` and grant a read-only role with document-level security scoped to the OpenEDR source.
5. For a separate OpenSearch destination or dedicated indices, adapt [the Logstash example](../integrations/wazuh/openedr-opensearch.conf) on a host with manager alert stream access. Use an approved CA, a dedicated writer restricted to `openedr-alerts-v1-*`, the Logstash keystore, and a persistent position file. Have the cluster owner create the index template and retention policy. Validate the pipeline before enabling forwarding, then query the integration index for the same `data.openedr_event_id`.

References for supported topology and syntax are the [Wazuh OpenSearch integration](https://documentation.wazuh.com/current/integrations-guide/opensearch/index.html) and [Wazuh rule testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html). The sample uses the Linux preview's normalized schema. The [upstream Windows guide](../getting-started/SettingFileBeat.md) describes log collection from `C:\ProgramData\edrsvc\log\*`. Capture representative logs on a licensed Windows test endpoint before implementing its normalization adapter.

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

Maintainer updates and same-repository maintainer PRs use `cormier-runners` when the runner path is enabled. Contributor validation uses GitHub-hosted runners. A private repository with forking disabled accepts proposals through issues or separately reviewed patches unless the organization provides another contribution path. Keep the workflow path ruleset and the maintainer-only release branch ruleset enabled. Use Codex review on the exact PR revision before merging or publishing a stable release.

For stable publication, open the maintainer release PR against main. Verify the Codex summary reports a completed code review with no unresolved findings on the final PR head. Merge while the PR head and resulting release commit have the same tree. Update the maintainer branch `release/<version>` to that release commit, push the matching `v<version>` tag, and dispatch `Preview CI and release` on that branch with the stable channel.
