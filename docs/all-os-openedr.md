# All OS OpenEDR preview

This software is subject to the terms of the Comodo Available Source License Agreement. See [the license](../LICENSE.md) and [redistribution notices](../NOTICE.md). Downstream distributions are free. Git history identifies the upstream code and downstream changes.

## Debian 13

Use the versioned `all-os-openedr_<version>_all.deb` asset in the private repository's releases. From the source checkout, build it with `sh packaging/debian/build.sh 0.1.0 ./dist` on Debian.

```sh
sudo apt install ./all-os-openedr_0.1.0_all.deb
sudo systemctl enable --now all-os-openedr.service
sudo systemctl status all-os-openedr.service
sudo head -n 1 /var/log/all-os-openedr/events.jsonl
```

The service runs as a dynamic, unprivileged user without network access. It emits process observations visible through procfs. Short-lived processes can be missed between polls. A restart may emit observations again, with the same event ID for processes that are still running. The preview collects names and PIDs. Command lines, environment values and file content are outside this event contract. Before leaving the preview active, configure and test rotation and retention with the Wazuh log collector in your environment. The collector reopens the output on each nonempty poll, so it follows a new file after rotation.

## Direct Wazuh ingestion and Wazah OpenSearch

1. Add [the JSON localfile stanza](../integrations/wazuh/localfile.xml) to the Wazuh agent's existing `ossec_config`. Use an endpoint with an enrolled Wazuh agent and verify that the logcollector can read the protected file.
2. Reserve Wazuh local rule IDs 110100 and 110101 and install [the rules](../integrations/wazuh/110100-openedr_rules.xml) under `/var/ossec/etc/rules/` on the manager. Test the [fixture](../integrations/wazuh/process-observed.json) with `/var/ossec/bin/wazuh-logtest`. It should match 110101 at level 3. Adjust collection and severity to the site's alert volume before rolling out broadly.
3. Validate the Wazuh configuration and restart the services during the approved test window. Confirm a benign endpoint observation in the manager's `alerts.json`.
4. Use Wazah's existing OpenSearch endpoint with an approved CA and a dedicated writer restricted to `openedr-alerts-v1-*`. Adapt [the Logstash example](../integrations/wazuh/openedr-opensearch.conf) on the host with access to the manager's alert stream. Use the Wazuh-documented server integration topology, inject credentials via the Logstash keystore, persist the position file, and create the index template and retention policy through the existing cluster owner. Validate the Logstash configuration before enabling forwarding.
5. Query the integration index for the same `data.openedr_event_id` to verify network, authentication, mapping and ingestion. Use a separate read-only identity for the management API.

References for supported topology and syntax are the [Wazuh OpenSearch integration](https://documentation.wazuh.com/current/integrations-guide/opensearch/index.html) and [Wazuh rule testing](https://documentation.wazuh.com/current/user-manual/ruleset/testing.html). The checked-in sample is for the Linux preview's normalized schema. Windows upstream telemetry is a separate adapter task.

## Kubernetes management preview

The stateless API serves recent OpenEDR alert fields from the dedicated OpenSearch index. The chart uses a private ClusterIP service, a disruption budget and multi-node scheduling. Use a Kubernetes version that supports `minDomains` in topology spread constraints and at least two eligible worker nodes. Before sending a bearer token across the network, use port forwarding for local testing or place a TLS-authenticating proxy in front of the service and apply your network policies.

Build `deploy/manager.Dockerfile` and make the resulting image available in your cluster's registry. Use a digest reference in the deployment. Create Kubernetes Secrets with the keys listed in [values.yaml](../deploy/chart/values.yaml), then supply a site-local values file to Helm.

```sh
helm upgrade --install openedr ./deploy/chart --namespace openedr --create-namespace \
  -f /path/to/site-values.yaml --wait --timeout 5m
```

`/healthz` checks the process, `/readyz` checks OpenSearch query access, and `/v1/events` requires the management bearer token. Rehearse pod disruption, an OpenSearch outage and recovery, upgrade, and rollback before production use. The preview provides read access to telemetry.

## Plugin contract

Agent plugins declare a name, API version, role and factory in the local registry. Collectors provide `poll()` and return normalized event dictionaries. Sinks implement `write(events)`. Select registered plugins with `--collector` and `--sink`. The initial registry provides the Linux process collector and JSON Lines sink. Register additional operator-reviewed factories in `all_os_openedr.agent.PLUGINS` and keep the schema compatible. Adding a general-purpose external plugin loader is tracked in the project.

## macOS

Run `sh packaging/macos/install.sh` for the installer stub. The native plan covers Apple silicon and Intel, the Endpoint Security entitlement, signed system extensions, notarization, and real-device install and removal tests.

## GitHub delivery

The project moves work from Backlog to Open, In Process, Pending Merge, Merged, and Released. Move an issue to Released when the published version contains it and the target's delivery checks pass. Daily upstream reconciliation imports clean changes from the corresponding upstream branch. A conflict, rewritten upstream history, or changes to licensing or workflow files requires maintainer review.

Maintainer updates and same-repository maintainer PRs use `cormier-runners` when the runner path is enabled. Contributor validation uses GitHub-hosted runners. A private repository with forking disabled accepts proposals through issues or separately reviewed patches unless the organization provides another contribution path. Keep the workflow path ruleset and the maintainer-only release branch ruleset enabled. Use Codex review on the exact PR revision before merging or publishing a stable release.
