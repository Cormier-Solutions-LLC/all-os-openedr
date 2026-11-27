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

Fork and exit events carry the kernel-reported parent PID and thread ID, and link to the parent's process identity when its birth was observed. The collector keeps a process identity while observed members of the thread group remain alive. Task exits record the raw Linux wait status and distinguish leader exits from worker-thread exits. Use the separate Audit collector for executable path evidence.

Each service start emits a new stream ID. Running processes whose births predate the stream can still emit lifecycle events with host PIDs. Their earlier process identities are unavailable in the new stream. Kernel event IDs incorporate boot ID, CPU, kernel sequence, and monotonic time. When the collector detects loss, it emits `process.stream_gap` and discards prior lineage so subsequent records do not inherit uncertain process identities. Review stream gaps before using the events for a complete timeline.

Merge the packaged `lifecycle-localfile.xml` into the Wazuh agent and install the packaged `110100-openedr_rules.xml` in the manager's local rules directory. Confirm rule IDs 110100 through 110103 are available. Rule 110102 covers lifecycle events and rule 110103 reports loss of continuity. The lifecycle stream can grow quickly on busy hosts. Configure rotation and retention for this separate path and verify that the Wazuh agent follows the new file after rotation.

The dedicated OpenSearch template indexes process and parent identities, stream IDs, exit wait status, and gap information. Install the updated template before creating new lifecycle indices. For an existing index, apply the additive fields to its mapping. Reindex lifecycle documents already stored before that mapping update if they need to participate in those queries. [OpenSearch explicit mappings](https://docs.opensearch.org/latest/mappings/)

### Investigate TCP connections

Enable the optional sensor on Debian 13 amd64 with the standard BTF-enabled kernel. Run it in the host PID and time namespaces.

~~~sh
sudo apt install bpftrace
sudo systemctl enable --now all-os-openedr-tcp.service
sudo systemctl status all-os-openedr-tcp.service
sudo tail /var/log/all-os-openedr-tcp/events.jsonl
~~~

The sensor records IPv4 and IPv6 TCP connect attempts that reach the kernel transmit path, outbound establishment, inbound acceptance, listening sockets, and TCP closure. It records local and remote addresses and ports where applicable. Direction describes the process's socket operation. Asynchronous events retain the identity of the connecting, accepting, or listening process. An outbound attempt followed by closure without establishment can also occur on connection refusal.

Use the Wazuh agent ID, boot ID, and `openedr_network_socket_id` to reconstruct a socket's timeline. Use `openedr_network_monotonic_ns` for event ordering and `openedr_network_namespace` to distinguish network namespaces. Match `openedr_file_actor_id` within the same agent and boot to join socket activity to file provenance. The process name is the group leader's kernel task name at capture time.

The service tracks socket activity observed after it starts. A listening socket can outlive the process that called listen, and an accepted socket may have lost its peer before acceptance. Early connect failures that never enter TCP transmission are outside this sensor's coverage. The sensor reads endpoint metadata without accessing packet payloads, including during encrypted TCP connections. [Linux TCP state handling](https://raw.githubusercontent.com/torvalds/linux/v6.12/net/ipv4/tcp.c) · [Debian bpftrace](https://manpages.debian.org/trixie/bpftrace/bpftrace.8.en.html)

Add the packaged `tcp-localfile.xml` to the endpoint and update `110100-openedr_rules.xml` on the Wazuh manager. Rule `110135` records TCP activity and rule `110136` reports detected evidence gaps. Apply OpenSearch template version 20 to new dedicated indices or add its TCP fields to active mappings. The local log holds a current 16 MiB file and three backups. Output is capped per process lifetime at 32 records per second, per Linux user at 64, and per endpoint at 128. The service reports detected buffer loss, socket tracking capacity, and output rate limits. Verify that your log collector follows the active file after rotation. [Wazuh localfile reference](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html)

### Investigate outbound DNS questions

Enable the optional DNS sensor on Debian 13 amd64 with a standard BTF-enabled kernel and `bpftrace`. Run it in the host PID and time namespaces.

~~~sh
sudo apt install bpftrace
sudo systemctl enable --now all-os-openedr-dns.service
sudo tail /var/log/all-os-openedr-dns/events.jsonl
~~~

The kernel sensor observes standard single-question A and AAAA requests sent to UDP port 53 on IPv4 and IPv6. It records the question name, type, resolver address, source endpoint, network namespace, and the transmitting process's lifetime ID. The kernel passes only the question name and type to the collector and the event contains no response, DNS transaction ID, or EDNS record. Unusual label bytes are represented with three-digit decimal escapes. Review access to DNS evidence because question names can reveal internal services.

A client sending to a local stub and the stub sending upstream produce separate observations with the identity of the sender on each leg. Use the endpoint, boot, namespace, timestamps, and resolver addresses to reconstruct the observed activity. A cache hit that produces a new client-to-stub datagram still has a client record. Cache hits and resolver APIs that generate no UDP request have no DNS question record. TCP fallback and encrypted DNS can produce connection evidence through the TCP service. The DNS sensor covers application-owned resolvers when they send the supported UDP requests. [DNS wire format](https://www.rfc-editor.org/rfc/rfc1035.html) · [DNS question count](https://www.rfc-editor.org/rfc/rfc9619.html)

Merge the packaged `dns-localfile.xml` into the Wazuh agent and update `110100-openedr_rules.xml` on the manager. Rule `110137` reports questions and rule `110138` reports detected gaps. Apply OpenSearch template version 21 to new dedicated indices or add its DNS fields to current mappings. The DNS service uses the same retention and output quotas as the TCP service, with a separate log and budget.

### Investigate HTTP and FTP requests

Enable the optional protocol sensor on Debian 13 amd64 with the standard BTF-enabled kernel and a unified cgroup hierarchy. The service compiles its packaged BPF source locally when it starts and observes the host cgroup hierarchy. Run it in the host PID and time namespaces.

~~~sh
sudo apt install clang-19 libbpf-dev libc6-dev linux-libc-dev
sudo systemctl enable --now all-os-openedr-protocol.service
sudo tail /var/log/all-os-openedr-protocol/events.jsonl
~~~

The sensor uses kernel socket and process lifetime identities. It observes IPv4 and IPv6 HTTP/1.0 and HTTP/1.1 GET and POST requests on outbound TCP port 80 and FTP RETR on outbound TCP port 21. Adjacent segments and retransmissions feed bounded stream parsers. The HTTP sensor follows Content-Length and chunked framing across requests on reused connections. FTP records the requested path and adds observed working-directory context from successful CWD or PWD replies. It preserves dot components because the server can resolve them through symlinks. After a successful CDUP, relative requests stay relative until a later reply provides a directory path.

Request records contain the method, endpoint tuple, and connecting process identity. When the bounded path can be represented, it is included. If only the method can be retained, the path scope is `unavailable`. This covers oversized paths and FTP arguments that resemble URLs. For HTTP, a valid hostname is retained with the represented path when available. The parser discards URL userinfo, queries, fragments, path parameters, credentials headers, and bodies from records. FTP credential commands and file contents are excluded from records. The collector processes bounded TCP bytes in memory and disables core dumps. Access controls on the evidence log also apply to hostnames and paths. [HTTP/1.1 message framing](https://www.rfc-editor.org/rfc/rfc9112.html) · [FTP control protocol](https://www.rfc-editor.org/rfc/rfc959.html)

The application socket ID binds the kernel socket cookie to the observed connection. Match these records to the separate TCP connection stream using the Wazuh agent ID, boot ID, network namespace, process lifetime, endpoint tuple, and monotonic observation window. The actor represents the connecting process when other processes inherit or share its socket.

The sensor starts from an observed TCP handshake and releases tracking when the kernel closes the socket. Gaps, reordered segments beyond the observed sequence, unsupported framing, or exhausted bounds stop interpretation for the affected connection. IP fragmentation and IPv6 extension headers are outside the current packet parser. HTTP upgrades and FTP AUTH stop plaintext interpretation after the server accepts the switch. Rejected switches leave plaintext observation active. HTTPS and encrypted FTP payloads remain opaque. The TCP service can still report their connection metadata.

Merge the packaged `protocol-localfile.xml` into the Wazuh agent and update `110100-openedr_rules.xml` on the manager. Rule `110139` reports request metadata and rule `110140` reports detected gaps. Apply OpenSearch template version 22 to new dedicated indices or add its fields to existing mappings. The service applies separate packet quotas per process and account, along with the normal event quotas and log retention. The kernel tracks up to 128 active protocol socket actors per UID. Capacity warnings preserve already tracked connections. The stanza resumes unread events from the active 16 MiB log after the Wazuh collector restarts. A prolonged outage can leave earlier events in rotated files that require separate recovery. [Wazuh log collector configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html#only-future-events)

### Trace file activity on a mounted filesystem

The optional Debian file provenance service monitors an explicitly chosen filesystem recursively. It reports opens, accesses, modifications, metadata changes, closes, creations, deletions, execution opens, and renames. File IDs are derived from the boot, filesystem, and Linux file handle. Renames carry the kernel-reported source and destination names when both directory entries are available. Display paths use directory handles resolved at collection time. Use the file ID to follow a file through path changes.

Choose a mounted filesystem dedicated to the data you want to observe. The service monitors the underlying filesystem instance, including activity through other mounts of that instance. Keep the collector log and forwarding queues on a separate filesystem so the forwarding pipeline cannot generate more events from its own writes. Begin with a dedicated ext4 volume and confirm the expected event volume and permissions before enabling forwarding.

```sh
printf 'OPENEDR_FILE_FILESYSTEM=/srv/openedr-provenance\n' |
  sudo tee /etc/default/all-os-openedr-file-provenance
sudo systemctl enable --now all-os-openedr-file-provenance.service
sudo tail /var/log/all-os-openedr-file-provenance/events.jsonl
```

The service uses `CAP_SYS_ADMIN` to open and mark the fanotify queue, then drops it before reading events. It keeps `CAP_DAC_READ_SEARCH` for path resolution and runs under a dynamic service account. File event details distinguish a kernel PID from a pidfd-verified process snapshot. A snapshot can supply observed real and effective UIDs and an actor ID that matches the polling collector's process event ID. Short-lived actors or unavailable credentials can leave only the kernel PID. These UIDs reflect the observation time.

Add the [file provenance localfile stanza](../integrations/wazuh/file-provenance-localfile.xml) to the enrolled agent and install the [OpenEDR rules](../integrations/wazuh/110100-openedr_rules.xml) on the manager. File activity uses rule `110105`. Rule `110106` reports a stream gap such as queue overflow. The kernel does not provide an exact dropped-record count for this queue. Install template version 4 for new dedicated OpenSearch indices to query file IDs, both rename paths, and actor IDs. Restrict access to the logs and indices because they can contain filenames and account identifiers.

Fanotify can coalesce operations. Rows with the same notification ID share one kernel report and observation time. Use that ID when counting notifications or interpreting operation order. Full-file read and write hashing, mapped I/O coverage, and remote changes on network shares need additional sensors. [Linux fanotify event semantics](https://man7.org/linux/man-pages/man7/fanotify.7.html)

### Investigate removable storage

On Debian, install `python3-pyudev` and enable the removable storage collector.

```sh
sudo apt install python3-pyudev
sudo systemctl enable --now all-os-openedr-removable-storage.service
```

The collector records USB block disks, other disks Linux flags as removable, and their partitions. USB monitoring requires a kernel with the USB controller and mass-storage drivers. Debian's standard kernel provides those drivers for this workflow. The collector reports attachment, removal, and mounts visible in its mount namespace. Startup snapshots use `device.present` and `device.mount_present`. A hash of the media's reported serial or WWN identifies it across connections. Serial-less media uses an attachment-scoped ID. Treat the identity as reported inventory data when investigating a device. Mount observations reflect the current mount table, so short transitions can coalesce.

Add the [removable storage localfile stanza](../integrations/wazuh/removable-storage-localfile.xml) to the endpoint and reload the [OpenEDR rules](../integrations/wazuh/110100-openedr_rules.xml) on the manager. Rule `110131` records device and mount observations. Rule `110132` records lost monitor continuity. Apply OpenSearch template version 18 to new dedicated indices or add the corresponding mappings to active ones.

Use file provenance on a mounted removable volume to trace its activity. Look for file events from the same Wazuh `agent.id` and `openedr_boot_id` within the mount window, and match `openedr_file_scope` to `openedr_device_mountpoint`. Match `openedr_file_filesystem_uuid` to `openedr_device_filesystem_uuid` when both are available. Use this UUID match on Btrfs because separate systemd mount namespaces can report different device numbers for the same volume. The Btrfs observation follows the source device named by the mount. For filesystems with a shared mount device number, `openedr_file_mount_device` and `openedr_device_mount_number` also provide a match when Linux does not report a UUID. Keep the mount window in either query because Linux can reuse device numbers and copied volumes can share a UUID. Apply the same media identity to follow the device across reconnections. [Debian mount information](https://manpages.debian.org/trixie/manpages/proc_pid_mountinfo.5.en.html) · [Btrfs mount example](https://btrfs.readthedocs.io/en/stable/btrfs-subvolume.html#mount-options)

#### Trace transfers to and from removable storage

The opt-in transfer sensor uses bpftrace and kernel BTF on standard Debian 13 amd64. Mount a designated ext4 filesystem on a fixed disk and one on removable media. Give each filesystem a distinct UUID and use dedicated paths in the host mount namespace. Install `bpftrace` and `python3-pyudev`. Set `OPENEDR_FIXED_VOLUME` and `OPENEDR_REMOVABLE_VOLUME` to those mount paths in `/etc/default/all-os-openedr-removable-copies`, then start `all-os-openedr-removable-copies.service`. The sensor checks both mount identities and discards the tracing state when either mount changes.

`file.copy_observed` identifies a successful `sendfile` or supported kernel `copy_file_range` transfer between two files. `file.copy_inferred` identifies a successful buffered write that matched a recent read made by the same thread using the same buffer, byte count, and sampled prefix and suffix. The samples stay in the kernel tracer. A match describes a byte range and can be part of a larger copy. Short or all-zero samples, explicit pipes, vectored I/O, memory mapping, and other mount namespaces are outside this sensor's coverage. Protect access to the logs, which contain local paths.

Merge the packaged `removable-copies-localfile.xml` into the Wazuh agent configuration and update `110100-openedr_rules.xml` on the manager. Rule `110133` reports a transfer with source and destination identities, paths and offsets, direction, actor identity and byte count. Rule `110134` reports a gap. In the search index, use the removable UUID, mount path on the removable side, Wazuh agent ID, boot ID, and observation window to link a transfer to the storage lifecycle. When the device reports a stable media identifier, match it as well. [Linux kernel file tracing](https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/read_write.c) · [Debian bpftrace documentation](https://manpages.debian.org/trixie/bpftrace/bpftrace.8.en.html)

The tracer limits the normal event stream to 64 records per second and emits a separate gap when it drops records. It retains the current 16 MiB JSON log and three rotated files. Forward alerts promptly when you need longer retention.

The tracer preserves paths through Linux's 4 KiB pathname buffer. A transfer whose kernel path cannot be resolved produces a path collection gap. The alert includes the original path bytes in hex for filenames outside UTF-8.

### Identify files opened for execution

Enable the optional executable collector for a chosen local filesystem. Select its mount root. For example, use `/` to observe executables on the root filesystem. Separate filesystems such as a separately mounted `/usr` need their own watch. The kernel supplies an open descriptor for each reported object. The collector hashes up to 32 MiB from that descriptor and records SHA-256, size, file format, filesystem device and inode, and a path when available. Actor fields include the kernel PID and, when available, a separate process snapshot from the accompanying pidfd. The service drops all effective capabilities after installing the watch. [Linux fanotify event descriptors](https://man7.org/linux/man-pages/man7/fanotify.7.html)

For offline verdicts, prepare a JSON file in the following format. Replace the example digest with a verified SHA-256 from an executable you have classified. The catalog accepts lowercase 64-character hashes and the values `trusted` and `untrusted`.

```json
{"schema": 1, "verdicts": {"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": "trusted"}}
```

```sh
sudo install -o root -g root -m 0644 ./verdicts.json /etc/all-os-openedr-executable-verdicts.json
printf 'OPENEDR_EXECUTABLE_FILESYSTEM=/\n' | sudo tee /etc/default/all-os-openedr-executable
sudo systemctl enable --now all-os-openedr-executable.service
sudo tail /var/log/all-os-openedr-executable/events.jsonl
```

The catalog is read once at startup. Replace the file and restart the service to apply an update. Events record the catalog SHA-256 where available. A valid catalog with no matching digest yields `unknown`. A missing or rejected catalog, a missing descriptor, a file over the limit, or a file that changes during measurement yields `unavailable`. Hashes are snapshots of the reported object when the collector reads it. The open can precede a failed launch. Compare with a `process.exec` event when successful execution matters. Interpreter reads, such as opening a script as input to `bash`, are outside the execution-open event. Local verdicts are investigation evidence. Use the separate workload policy for enforcement.

Merge the [executable localfile stanza](../integrations/wazuh/executable-localfile.xml) into Wazuh and update the packaged `110100-openedr_rules.xml` on the manager. Reserve rule IDs `110107` for opens and `110108` for local untrusted matches. Queue overflow uses `110106`. Install template version 5 or add the new executable fields to existing dedicated OpenSearch index mappings before querying by digest or verdict. The collector computes verdicts locally while the Wazuh path is unavailable.

### Apply a signed executable verdict policy

Use a dedicated OpenSSH signing key on the policy administrator's workstation. Install the public key on each endpoint as an allowed signer under `/etc/all-os-openedr/executable-policy-signers`. Use a unique 32-character lowercase hexadecimal target per endpoint. Install `/etc/all-os-openedr/executable-policy.json` with `schema` set to `1` and `target` set to that ID. The directory and both files require root ownership and root-only write access. The broker and executable sensor must use `/etc/all-os-openedr-executable-verdicts.json` as their catalog.

An allowed signers entry uses the principal recorded in the signed document and the executable policy namespace.

```text
fleet-policy namespaces="all-os-openedr-executable-policy-v1" ssh-ed25519 <public-key>
```

Create a JSON document with `schema` set to `2`, the endpoint `target`, an increasing integer `revision`, the `signer` principal, and a `verdicts` object mapping lowercase SHA-256 hashes to `trusted` or `untrusted`. The complete document is limited to 1 MiB. Each revision specifies the full catalog. To restore older verdicts, sign those verdicts with a revision higher than the active revision.

```sh
# On the signing workstation.
ssh-keygen -Y sign -f ~/.ssh/openedr-policy -n all-os-openedr-executable-policy-v1 catalog.json

# On the enrolled endpoint, after transporting the exact document and signature.
sudo all-os-openedr-executable-policy apply catalog.json catalog.json.sig
sudo all-os-openedr-executable-policy status
```

The updater verifies the exact bytes and serializes approved writes. The active file carries its revision through a reboot. Leave the active file under the updater's control to preserve replay protection. The running sensor reloads the catalog when the file changes. Subsequent broker decisions and executable observations report the same catalog digest. Signed verdicts apply to the managed launcher. Kernel IMA approval has its own controls and procedure.

The command writes applied or rejected receipts to `/var/log/all-os-openedr-policy/changes.jsonl`. Use `sudo all-os-openedr-executable-policy status --record` to record the current revision if the original receipt was lost. Create the log with that command before enabling the packaged [Wazuh localfile stanza](../integrations/wazuh/policy-localfile.xml). Reload the [Wazuh rules](../integrations/wazuh/110100-openedr_rules.xml) on the manager. Rule `110129` records policy receipts and `110130` alerts on rejected updates. Apply the current OpenSearch template to new dedicated indices or add its policy fields to the active index.

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

### Monitor changes to Debian configuration

Choose the existing files and directory trees that control services, scheduling, or user startup on the endpoint. For example, this monitors service overrides, system cron entries, and one user's service and shell configuration. Select paths that exist on the target host. The generator resolves symbolic links and emits rules for the resulting paths.

```sh
sudo all-os-openedr-audit-rules \
    --watch-config /etc/systemd/system \
    --watch-config /etc/cron.d \
    --watch-config /home/operator/.config/systemd/user \
    --watch-config /home/operator/.profile > openedr-configuration.rules
cat openedr-configuration.rules
sudo install -o root -g root -m 0600 openedr-configuration.rules /etc/audit/rules.d/41-openedr-configuration.rules
sudo augenrules --load
sudo auditctl -l -k openedr-config-change
sudo ausearch -k openedr-config-change -i
```

These rules report successful write access and attribute-changing operations. A write-capable open can be recorded before any write occurs. Audit records filesystem operations such as rename and unlink within the configured scope and retains the process, effective UID, and login UID when set. Ordinary reads and byte-level changes are outside this rule set. For directory trees, verify coverage after a mount or a watched directory changes. Check for earlier Audit rules that could win the first match and monitor the `lost` counter during normal endpoint activity. [Debian Linux Audit filters](https://manpages.debian.org/trixie/auditd/auditctl.8.en.html)

Reuse the Audit localfile stanza above. Reserve rule ID `110118` and update the manager's `110110-openedr-execution_rules.xml` before generating a benign change. Search the Wazuh alerts for `rule.id:110118`. The alert preserves the grouped Audit record, including additional paths on operations such as rename. Use the alert's executable, PID, user fields, and full Audit record to investigate. File contents are outside the alert. Roll back by removing `41-openedr-configuration.rules` and deleting only those rules with `sudo auditctl -D -k openedr-config-change`. Confirm `auditctl -l -k openedr-config-change` no longer lists the configuration watches. If the endpoint uses immutable Audit rules, schedule a reboot for the change to take effect.

### Kernel execution approval on a managed volume

On Debian 13, Linux Integrity Measurement Architecture (IMA) can require an approved hash before direct execution or executable file mapping from a dedicated ext4 filesystem. The rules follow that filesystem's UUID. Use a separate volume for managed executable files. Keep the system root and operator tools on their existing filesystems. IMA enforces the policy in the kernel, including while Wazuh is unavailable. [Linux IMA policy](https://ima-doc.readthedocs.io/en/latest/ima-policy.html)

Mount the volume and prepare a root-owned verdict catalog using the schema in [Identify files opened for execution](#identify-files-opened-for-execution). Add `trusted` entries only for independently verified files. Approve the executable after placing its final bytes on the volume. The command checks the exact file against the catalog and records its SHA-256 in the kernel's `security.ima` attribute. Approval and revocation apply to that file object, including any hard links to it.

```sh
sudo all-os-openedr-ima approve --filesystem /srv/openedr-exec \
    --catalog /etc/all-os-openedr-executable-verdicts.json /srv/openedr-exec/approved-program
sudo all-os-openedr-ima policy --filesystem /srv/openedr-exec > openedr-ima-policy
cat openedr-ima-policy
```

On a host with a fresh IMA configuration and appraisal in enforce mode, stage and load the reviewed policy from a root-owned path outside the protected volume. On the standard Debian 13 kernel, loading a custom policy uses the available policy update for the current boot. A custom policy replaces optional built-in rules. If the host already uses IMA, incorporate these rules into its complete policy through the site's approval process. A host in IMA log or fix mode needs an enforce-mode boot for this workflow. Test an approved and an unapproved executable before depending on the volume.

```sh
sudo install -o root -g root -m 0600 openedr-ima-policy /root/openedr-ima-policy
printf '%s\n' /root/openedr-ima-policy | sudo tee /sys/kernel/security/ima/policy >/dev/null
```

To persist a tested custom policy on a fresh Debian host, have systemd load it at boot from `/etc/ima/ima-policy`. Retain the previous configuration. To roll back, restore the previous boot policy or remove the added file if there was no previous policy, then reboot. To withdraw one file's local approval, run `sudo all-os-openedr-ima revoke --filesystem /srv/openedr-exec /srv/openedr-exec/approved-program`. The next appraised operation uses the current file and approval. Approve copies that lack the attribute before execution. Code read as ordinary interpreter input is outside the direct execution and executable mapping hooks.

#### Require integrity approval for native code owned by ordinary users

Add `--appraise-user UID` for each ordinary account that needs native execution protection beyond the managed volume. The kernel requires an IMA signature for non-root-owned code when a direct launch uses or would acquire a selected real or effective UID. The rules also cover initial executable file mappings and deny adding execute permission to an existing file mapping in that scope. They apply to paths such as a user's home and download directories. Administrator-controlled root-owned tools retain their normal behavior outside the enrolled volume. Existing approval rules continue to apply on the enrolled volume. [IMA policy matching](https://github.com/torvalds/linux/blob/v6.12/security/integrity/ima/ima_policy.c) · [IMA execution and mapping hooks](https://github.com/torvalds/linux/blob/v6.12/security/integrity/ima/ima_main.c)

```sh
sudo all-os-openedr-ima policy --filesystem /srv/openedr-exec \
    --launcher-uid "$(id -u openedr-broker)" \
    --appraise-user "$(id -u USER)" > openedr-ima-policy
```

For account-only appraisal on a host without an enrolled volume, omit `--filesystem` and `--launcher-uid`. Use a dedicated broker UID outside the selected accounts when combining the policies. Review existing user software and confirm the IMA keyring and rules before enabling the policy. Verify a benign unsigned program, a file-backed executable mapping, and administrator-installed tools under a selected account. On an enrolled volume, also verify approved native execution and a managed containment launch. A denied direct launch remains denied. Use the enrolled broker entry point for a contained launch. Ordinary interpreter reads outside the managed volume, anonymous executable memory, and other executing accounts require separate coverage. Restore the previous boot policy and reboot to roll back the selected accounts.

When IMA rejects an executable after Linux has started replacing the calling process, the caller may report `SIGSEGV`. Check the matching kernel integrity denial to identify the policy decision. [Linux execve failure behavior](https://manpages.debian.org/trixie/manpages-dev/execve.2.en.html)

For Wazuh alerts, install the packaged Audit dispatcher configuration and the separate JSON input. This keeps each IMA appraisal failure searchable even when the original Audit log groups it with syscall records for another Wazuh rule. The dispatcher records appraisal failures and IMA denials of changes to executable file mappings. It includes the raw record, path, failure cause, process ID, and login UID. Kernel appraisal mode determines whether an appraisal failure denies the operation. [Debian Audit plugins](https://manpages.debian.org/trixie/auditd/auditd-plugins.5.en.html)

```sh
sudo install -d -o root -g root -m 0750 /var/log/all-os-openedr-ima
sudo touch /var/log/all-os-openedr-ima/audit.jsonl
sudo chown root:root /var/log/all-os-openedr-ima/audit.jsonl
sudo chmod 0600 /var/log/all-os-openedr-ima/audit.jsonl
sudo install -o root -g root -m 0640 /usr/share/all-os-openedr/wazuh/ima-dispatch.conf \
    /etc/audit/plugins.d/all-os-openedr-ima.conf
sudo auditctl --signal reload
```

Merge the packaged `ima-localfile.xml` into the enrolled Wazuh agent. Update `110100-openedr_rules.xml` on the manager and verify rule ID `110119` is available. Install the current OpenSearch template to map IMA UID, login UID, Audit serial, and failure cause in new dedicated indices. Configure rotation for the JSON log with root-only file permissions. To stop forwarding, remove the installed Audit plugin configuration and reload Audit before removing the package.

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

### Automatically contain unknown managed applications

Install `bubblewrap` and `python3-seccomp` on Debian 13 amd64. Configure a dedicated unprivileged service account and use the packaged launcher as the entry point for an administrator-managed service. Set its catalog path to the administrator-owned SHA-256 catalog described above. Each launch reads the current catalog, including when Wazuh is offline. An `untrusted` entry blocks the launch. A `trusted` ELF may run natively when the file and its ancestors are administrator-controlled. An unknown ELF, a trusted ELF from a writable location, or a supported shell script goes through the isolated launch path. An unavailable catalog or failed isolation blocks execution.

Keep the service arguments and native environment under administrator control. Approve native execution only for applications that load administrator-controlled code. Keep interpreters and programs that accept user-supplied code out of the native approval catalog for this service.

Use a dedicated service cgroup to bound the resources of the application and its descendants. Create the root-owned log directory with `sudo install -d -m 0750 -o root -g root /var/log/all-os-openedr-containment`. Customize this example before installing and starting the unit. Stop the managed service before restoring a prior catalog or entry point.

```ini
[Service]
Type=oneshot
User=openedr-workload
NoNewPrivileges=yes
ProtectHome=yes
TasksMax=64
MemoryMax=256M
CPUQuota=100%
ExecStart=/usr/bin/all-os-openedr-launch --catalog /etc/all-os-openedr-executable-verdicts.json --timeout 30 /srv/openedr-workload/program
StandardError=append:/var/log/all-os-openedr-containment/launches.jsonl
```

The launcher hashes and copies the opened file before handing its sealed bytes to Bubblewrap. The isolated process starts with private file, network, IPC, and PID namespaces and a bounded scratch directory. A syscall filter denies socket creation and cross-process memory operations. The read-only view includes the captured program and three Debian amd64 glibc runtime files for static and basic glibc-linked ELF programs. The launcher discards isolated process I/O and returns its exit status. Desktop sessions, direct execution outside the launcher, and applications requiring other libraries or host data need additional controls and qualification. [Bubblewrap execution options](https://manpages.debian.org/trixie/bubblewrap/bwrap.1.en.html)

For a managed shell service, pass the script path directly as the launcher program, followed by its arguments. The launcher supports fixed dash and Bash shebangs or `env` aliases for `sh`, `dash`, and `bash`, with one optional `-e`, `-u`, `-eu`, or `-ue` option. Use `env -S` when specifying an option with an `env` shebang. The selected shell reads a non-executable copy inside the sandbox. The runtime supplies the selected shell and the Debian `/bin/sh` alias, with scratch storage for shell built-ins and child shells. Scripts requiring other commands, profile files, or other interpreters need additional runtime support. Launch records identify the selected interpreter. Direct interpreter commands outside the launcher remain outside this control.

On Debian 13 amd64, `all-os-openedr-launch --allow-python --catalog CATALOG /absolute/path/tool.py` enables contained Python 3.13 scripts for a managed service. Use `#!/usr/bin/python3`, `#!/usr/bin/python3.13`, or an equivalent `env` shebang. An optional `-u` is accepted. The launcher fixes the interpreter to the Debian `/usr/bin/python3.13` runtime and passes the sealed script copy as its input. It mounts the interpreter and standard library read-only and uses isolated Python startup with site initialization and bytecode writes disabled. Install the Debian `python3.13` package and keep its runtime administrator-controlled. Python packages installed in a virtual environment or in Debian's separate `dist-packages` directory stay outside the sandbox. Standard-library extensions that require extra native libraries use the administrator-approved shared library grants on the broker route. [Python command-line options](https://docs.python.org/3.13/using/cmdline.html) · [Debian Python package](https://packages.debian.org/trixie/python3.13)

Review the local JSON decisions, including SHA-256, catalog ID, disposition, exit code for isolated launches, and the sandbox supervisor PID when available. On enrolled endpoints, merge `containment-localfile.xml` from `/usr/share/all-os-openedr/wazuh/` into the agent configuration. Install the updated `110100-openedr_rules.xml` on the manager and reserve rule IDs 110120 through 110123. Configure log retention for the service's append file and restart the managed service after rotating it.

Bubblewrap reports the sandbox supervisor as its namespaces are created. The launcher writes an `executable.sandbox_created` record at that point, followed by the terminal decision with the same `openedr_containment_launch_id` and its own timestamp. A creation record can precede an isolation success, a timeout, or a setup failure. Treat a launch with only a creation record as awaiting a terminal decision. A local policy denial can have only a decision record. Each record has its own event ID so the forwarder retains both. Wazuh uses rule 110123 for creation and rules 110121 and 110122 for blocked and isolated decisions. [Bubblewrap status notifications](https://manpages.debian.org/trixie/bubblewrap/bwrap.1.en.html)

Install OpenSearch template version 13 for new dedicated indices. If the current write index already exists, ensure it has the `data.openedr_containment_launch_id` keyword and `data.openedr_containment_pid_namespace` long mappings, or use a new index before exercising the launch lookup. Search by the launch ID printed by `all-os-openedr-run` or shown on the Wazuh alert. The authenticated manager serves up to four matching records at `GET /v1/containment/<launch-id>`. The lookup returns the caller UID, application alias, digest, outcome, and available sandbox identifiers. It excludes program arguments, paths, and workload I/O. Keep access limited to operators authorized for the dedicated index.

Enable the [kernel process lifecycle collector](#kernel-process-lifecycle) on the same endpoint and forward both logs under the same Wazuh agent. On an existing write index, add `data.openedr_containment_monitor_pid`, `data.openedr_containment_fork_after_ns`, and `data.openedr_containment_fork_before_ns` as long fields before recording new launches.

Use the same bearer token with `GET /v1/containment/<launch-id>/processes`. The manager finds the supervisor's kernel fork using the endpoint, boot, parent PID, and the launcher’s monotonic fork window. It follows parent process lifetime IDs from that fork and includes observed exec and task exit events. The response contains the root process ID, the available fork records, and the observed lifecycle events. Wait for the creation and fork records to arrive if the lookup reports `creation_unavailable` or `root_unavailable`. An ambiguous match is reported without linking unrelated processes. The response is bounded to 128 processes, eight descendant levels, and 256 exec or exit records. Short-lived processes can be visible through kernel events. Collection gaps and indexing latency can leave parts of the tree unavailable. [Linux process connector timestamps](https://github.com/torvalds/linux/blob/v6.12/drivers/connector/cn_proc.c)

#### Inspect file and socket results from a contained application

On Debian 13 amd64 with kernel Audit, BTF, and syscall tracepoints, install `bpftrace` and enable `all-os-openedr-containment-audit.service` before starting new application requests. Use `systemctl edit all-os-openedr-launch@.service` and add the following broker opt-in.

```ini
[Service]
Environment=OPENEDR_CONTAINMENT_AUDIT=1
```

The delegated broker starts a fresh kernel Audit session under its dedicated account. The collector observes selected native amd64 file opens and socket creation after the sandboxed program starts. It scopes capture to that Audit session and the sandbox mount namespace. The Audit session identifies the managed launch, and the launch record preserves the authenticated requester UID. This works alongside the existing sandbox and seccomp filter. If a kernel security setting prevents tracing or Audit session creation, the launch policy still runs. [Debian bpftrace reference](https://manpages.debian.org/trixie/bpftrace/bpftrace.8.en.html)

Merge the packaged `containment-audit-localfile.xml` into the same Wazuh agent configuration as the launch log. Reserve Wazuh rule 110124. Configure retention for the local audit output and index these fields with template version 13 or add the new properties from that template to the current write index.

Use `GET /v1/containment/<launch-id>/activity` with the management bearer token. Each entry includes the operation, PID, result, and errno for a failure. The lookup returns up to 128 records and reports truncation when the collection limit is reached. Use the result with the launch disposition and process tree. A failed open can indicate that a path was absent in the sandbox. File paths, syscall arguments, and workload data are omitted. An unavailable session or missing events indicate an evidence gap. Stop and disable the collector and remove the service drop-in to stop collection.

#### Use the launcher with a kernel-protected execution volume

Apply the [IMA volume policy](#kernel-execution-approval-on-a-managed-volume) before deploying this service. Read the chosen ext4 volume's UUID with `findmnt -nr -o UUID --mountpoint /srv/openedr-exec`. Put that value in the launcher command and require the mount in the unit. The example replaces the service's previous launch command.

```ini
[Unit]
RequiresMountsFor=/srv/openedr-exec

[Service]
ExecStart=
ExecStart=/usr/bin/all-os-openedr-launch --catalog /etc/all-os-openedr-executable-verdicts.json --execution-volume /srv/openedr-exec REPLACE_WITH_VOLUME_UUID /srv/openedr-exec/program
```

The launcher checks the mount, UUID, and opened file's device before it runs the program. A trusted file must also have the matching approval from `all-os-openedr-ima approve`. Native execution uses the original file descriptor, so the kernel still appraises that file. Unknown files run from a sealed copy in the isolated environment. The UUID is included in the launch decision. To withdraw native trust, stop the service, revoke the IMA approval, then update the catalog and restart the service. The catalog and the kernel approval are separate inputs.

After each deployment or boot-policy change, verify on the endpoint that a benign unsigned file on the volume is denied when launched directly and runs in isolation through the managed service. Verify that the enrolled service blocks execution when the volume is unavailable or replaced. This option validates the volume and its local approval attribute. The boot-time IMA policy supplies the direct-execution enforcement.

#### Protect interpreter reads on the enrolled volume

Use `--launcher-uid` when ordinary file opens should also require IMA approval. Set `User=openedr-workload` in the managed service and reserve that fixed non-root UID for the administrator-managed launcher. Keep interactive logins and delegation to that account disabled. Stage files and apply approvals as root. Ordinary non-root processes need valid IMA approval to open a file for reading, including when passing it to an interpreter. The launcher account can read an unsigned candidate and execute its snapshot inside the sandbox. IMA still appraises direct execution and executable mappings for that account.

```sh
sudo all-os-openedr-ima policy --filesystem /srv/openedr-exec \
    --launcher-uid "$(id -u openedr-workload)" > openedr-ima-policy
```

Review and load the generated policy using the IMA procedure above. This covers file reads throughout the selected filesystem, so keep ordinary data and application state on other volumes. Apply it at boot before user services acquire file descriptors. Verify that an ordinary account can open an approved fixture, that its shell cannot read an unsigned fixture, and that the managed service still isolates the unsigned fixture. The kernel records appraisal failures for the existing Wazuh rule `110119`.

#### Allow ordinary users to request contained launches

On Debian 13 amd64, install Bubblewrap and the Python seccomp bindings. Create a locked, dedicated broker account with a stable UID and a separate group for users allowed to request launches.

```sh
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin openedr-broker
sudo groupadd --system openedr-launch
sudo usermod -aG openedr-launch USER
sudo install -d -m 0750 -o root -g root /var/log/all-os-openedr-containment
sudo all-os-openedr-ima policy --filesystem /srv/openedr-exec \
    --launcher-uid "$(id -u openedr-broker)" > openedr-ima-policy
```

Apply the policy at boot with the volume enrolled as described above. Keep the staged programs and their parent directories root-owned with group and other writes disabled. Make the root-owned verdict catalog readable by the broker. Install the following policy as `/etc/all-os-openedr-launch.json` with owner `root:openedr-broker` and mode `0640`. Use the volume's actual UUID and the UID from `id -u USER`.

```json
{
  "schema": 1,
  "filesystem": "/srv/openedr-exec",
  "uuid": "REPLACE_WITH_VOLUME_UUID",
  "catalog": "/etc/all-os-openedr-executable-verdicts.json",
  "applications": {
    "my-app": {"program": "my-app", "uids": [1000], "arguments": [], "interactive": true, "document": true, "export": true}
  }
}
```

Enable the listener with `sudo systemctl enable --now all-os-openedr-launch.socket`. After signing in again to pick up group membership, the authorized user can run `all-os-openedr-run my-app`. Local Unix credentials identify the caller. The policy identifies authorized UIDs, paths relative to the enrolled volume, and fixed arguments. The client prints the decision and audit ID and returns the contained program's exit status. Each allowed launch uses the sandbox, including for a catalog-trusted program. Keep the broker UID reserved for this service and update the policy before removing or reassigning a caller UID.

Set `interactive` to `true` for applications that need line-oriented input and output. The user can type input with `all-os-openedr-run --interactive my-app` or select a readable input file with `all-os-openedr-run --interactive my-app < document.txt`. The sandbox sees anonymous pipes. Its filesystem, network, devices, and process namespace use the same isolation policy. Standard output and error are combined as plain UTF-8 text, with terminal controls replaced and a 256 KiB output limit. The launch decision and audit ID go to standard error. Use this mode for line-oriented commands that finish within 30 seconds. Full-screen terminal and graphical applications require separate support. Ctrl+C, disconnecting the client, and exceeding its output limit end the session. The default launch keeps input and output disconnected.

Set `document` to `true` for an application that takes a document path as its last argument. An authorized user can run `all-os-openedr-run --interactive --document "./document.txt" my-app`. The client reads a regular file up to 8 MiB with the user's permissions. The sandbox receives a seekable, read-only snapshot at `/run/openedr/document` and the original host path stays outside the sandbox. The broker records its launch decision without the document name or contents. Omit `--interactive` for applications that can run without terminal I/O. [Linux file sealing](https://manpages.debian.org/trixie/manpages-dev/memfd_create.2.en.html) · [Bubblewrap file binding](https://manpages.debian.org/trixie/bubblewrap/bwrap.1.en.html)

Set `"python": true` on an enrolled application to allow a staged script with a supported Python shebang. For a script that accepts an input path and writes to an output path, enable `document` and `export` on the same entry. An enrolled user can run `all-os-openedr-run --document "./data.json" --export "./result.json" my-app`. The sandbox still uses the existing network, syscall, and namespace controls. The record identifies the interpreter as `python3.13`. Keep the managed volume's IMA read appraisal enabled for the enrolled accounts to protect that script from direct interpreter reads.

An administrator can grant a staged application up to 16 additional Debian amd64 shared libraries using its `libraries` list. Install the required packages from the Debian repositories. Specify each required library, including transitive dependencies, by its installed name under `/usr/lib/x86_64-linux-gnu`. The broker checks the directory, resolved files, and symlinks and mounts each approved file read-only at its named path. Existing base runtime files remain reserved. A missing or unsafe library blocks the launch with `runtime_library_unavailable`. The default exposes only the existing minimal runtime. [Debian dynamic linker](https://manpages.debian.org/trixie/manpages/ld.so.8.en.html) · [Bubblewrap read-only binds](https://manpages.debian.org/trixie/bubblewrap/bwrap.1.en.html)

For example, install Debian's `jq` package and stage `/usr/bin/jq` as a root-owned `jq` binary on the enrolled volume. Add this entry to `applications` and run `all-os-openedr-run --interactive --document "./data.json" jq` as the enrolled user. [Debian libjq1 files](https://packages.debian.org/trixie/amd64/libjq1/filelist) · [Debian libonig5 files](https://packages.debian.org/trixie/amd64/libonig5/filelist)

```json
{
  "jq": {
    "program": "jq",
    "uids": [1000],
    "arguments": ["-c", "."],
    "interactive": true,
    "document": true,
    "libraries": [
      "/usr/lib/x86_64-linux-gnu/libjq.so.1",
      "/usr/lib/x86_64-linux-gnu/libonig.so.5"
    ]
  }
}
```

To offer a contained document action in a desktop file manager, install an application entry such as `~/.local/share/applications/openedr-my-app.desktop`. Use the MIME type supported by the enrolled command. This example opens one local text document in a terminal and leaves the user's default application selection in place. [Desktop Entry file arguments](https://specifications.freedesktop.org/desktop-entry/latest/exec-variables.html)

```ini
[Desktop Entry]
Type=Application
Name=Open text in containment
Exec=/usr/bin/all-os-openedr-run --interactive --document %f my-app
Terminal=true
MimeType=text/plain;
```

Set `export` to `true` for a command that can write to a pre-created output file. `all-os-openedr-run --document "./document.txt" --export "./edited.txt" my-app` passes `/run/openedr/document` followed by `/run/openedr/export` after any fixed arguments. The application can modify the export file in place within a private memory-backed filesystem. The client saves the result only when the isolated application exits successfully and the export is at most 8 MiB. The user chooses a new destination on a local filesystem that supports anonymous temporary files, such as ext4. The client creates the destination atomically with owner-only permissions and leaves existing files and symlinks untouched. The client keeps the destination out of the broker request and sandbox. [Linux anonymous temporary files](https://manpages.debian.org/trixie/manpages-dev/open.2.en.html)

#### Open a downloaded program in containment

Add `"download_uids": [1000]` to the root-owned launch policy for the ordinary accounts allowed to open selected programs. Keep the same broker account, socket group, catalog ownership, and package dependencies. An installation that only handles downloads can use `schema`, `catalog`, and `download_uids` and omit the staged application settings. Apply the account IMA policy to the same users to restrict direct native execution.

Run `all-os-openedr-run --interactive --download "./selected-program"` or select **Open in All OS OpenEDR Containment** through the desktop application chooser. The packaged entry uses the desktop's terminal and accepts one selected file. The client reads up to 32 MiB with the user's permissions. The broker seals and hashes the exact bytes before making the catalog decision. An untrusted verdict or unavailable catalog prevents launch. Eligible unknown and trusted downloads both start under containment. The enrolled application route remains available for administrator-staged programs.

Set `"download_python": true` in the root-owned launch policy to enable downloaded Python scripts for the enrolled download UIDs. A script with a supported shebang can receive input over the interactive pipe. The packaged desktop action also registers for `text/x-python` files. Direct reads by a host interpreter outside an IMA-protected volume remain outside this launch path.

On a GIO-based desktop, a protected user can select the containment entry as the default for a supported executable type. For example, `gio mime application/x-pie-executable all-os-openedr-contain-download.desktop` routes ordinary desktop opens of that type through containment. Apply the association to the file types used by that account. The package leaves desktop defaults to the administrator or user.

The downloaded program receives the same minimal runtime, private scratch space, and syscall restrictions as other contained programs. The optional top-level `download_libraries` list grants individual read-only shared libraries to all contained downloads for the enrolled accounts, using the same file and ownership checks as staged applications. Keep the list specific to the runtime needed by those accounts. The user can connect plain-text terminal input and output. The broker records the authenticated UID and digest under `downloaded file`. The original pathname stays out of the broker request. Normal shell execution follows the kernel policy. Use the containment action to open a denied download. [Linux file sealing](https://manpages.debian.org/trixie/manpages-dev/memfd_create.2.en.html) · [Desktop file arguments](https://specifications.freedesktop.org/desktop-entry/latest/exec-variables.html)

Test the direct IMA denial, authorized request, and unauthorized request as ordinary users before enrollment. The JSON launch record includes the authenticated caller UID and the enrolled application name for authorized requests. Wazuh uses the existing isolated and blocked launch rules. Apply the updated OpenSearch template for new indices. Stop and disable the socket to withdraw delegated launch access.

### Verify that endpoint protection is active

On a Debian endpoint with the broker and an IMA-managed execution volume, prepare the two fixed probe scripts on that volume. Use the mount path from the broker's policy.

```sh
sudo all-os-openedr-health --prepare-ima /srv/openedr-exec
sudo all-os-openedr-health
sudo systemctl enable --now all-os-openedr-health.timer
```

The root-only check asks the unprivileged broker to run the approved script directly, confirm that IMA denies the unsigned copy, and run a separate script in the actual sandbox. The sandbox probe requires a private writable `/tmp` and verifies that the host's `/etc/passwd` is absent. The IMA result covers direct execution on the configured volume. An account-only download policy reports `execution_volume_unconfigured`. The expected kernel denial references `.openedr-health/unsigned` on the configured mount.

The command prints one JSON record and returns `0` when protection, forwarding, and sensor checks are ready. A `1` indicates degradation. Check `openedr_health_ima`, `openedr_health_broker`, `openedr_health_forwarder`, and `openedr_health_sensors` to locate the failure. The `openedr_health_sensor_*` fields show the systemd state of each packaged sensor. Enabled sensors that stop, fail, or restart degrade the check, as do missing or unreadable sensor units. An intentionally disabled or masked optional sensor is reported separately. An active sensor can be healthy with no recent events. Join these records to endpoint evidence using the Wazuh agent ID and boot ID.

Forwarding status reflects the fresh local Wazuh agent connection. Confirm end-to-end delivery by checking for the event ID on the manager.

The opt-in timer samples every five minutes and appends to `/var/log/all-os-openedr-health/checks.jsonl`. Create the log with `sudo systemctl start all-os-openedr-health.service`, then add the packaged Wazuh localfile stanza to the endpoint and reload the rules on the manager. Use rule `110127` to find samples and `110128` for degraded protection, forwarding, or sensor service state. Apply OpenSearch template version 23 to new dedicated indices or add the sensor health fields to the active index. Include the local file in your site's log retention policy. [Wazuh localfile](../integrations/wazuh/health-localfile.xml) · [Wazuh rules](../integrations/wazuh/110100-openedr_rules.xml)

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

### Isolate a Debian endpoint through Wazuh

Enable this response only on enrolled Debian 13 endpoints with an out-of-band recovery console. The endpoint's kernel blocks IPv4 and IPv6 input, output, and routed forwarding while the lease is active. It keeps loopback, IPv6 neighbor discovery, and the outbound TCP connection to one configured Wazuh manager address. Existing endpoint firewall rules still apply. Use a stable address and route, and check management and console access before enabling the response. Layer 2 forwarding, separately attached network namespaces, and a privileged process that can alter firewall rules require their own controls.

1. Install `nftables` and `openssh-client` on the endpoint. Create `/etc/all-os-openedr/` owned by root. Give each endpoint a unique 32-character lowercase hexadecimal ID, set its enrolled Wazuh agent ID, and specify its manager's literal address and TCP port in root-owned `response.json` with mode `0600`. For example, `{"endpoint":"e24d48c344944aa9a902cbc5ed56b749","agent":"001","manager":{"ip":"192.0.2.10","port":1514}}`.
2. Put each approved operator's public signing key in root-owned `response-signers` with mode `0600`. An allowed-signers entry starts with the operator identity, then `namespaces="all-os-openedr-response-v1"` and the public key. Keep the private keys on operator workstations. Give the dispatch account the Wazuh `active-response:command` permission only for the intended `agent:id` or group. [OpenSSH allowed signers](https://man.openbsd.org/ssh-keygen#ALLOWED_SIGNERS) · [Wazuh RBAC](https://documentation.wazuh.com/current/user-manual/api/rbac/reference.html)
3. Install the packaged Wazuh launcher and prepare its audit log as shown below. Enable Active Response and add [the response localfile stanza](../integrations/wazuh/response-localfile.xml) on the endpoint. Reload the [OpenEDR rules](../integrations/wazuh/110100-openedr_rules.xml) on the manager. Use the current dedicated OpenSearch template if using that forwarding route. Keep automatic alert triggers disabled for this launcher.

```sh
sudo install -o root -g wazuh -m 0750 \
  /usr/share/all-os-openedr/wazuh/all-os-openedr-response \
  /var/ossec/active-response/bin/all-os-openedr-response
sudo install -d -m 0700 /var/log/all-os-openedr-response
sudo touch /var/log/all-os-openedr-response/actions.jsonl
sudo chmod 0600 /var/log/all-os-openedr-response/actions.jsonl
```

Select the alert and verify its endpoint in Wazuh. Use a synchronized signer workstation and endpoint clock. The endpoint accepts an approval for up to 60 seconds after signing. The example signs a 120-second lease and sends it to agent `001`. Set `ENDPOINT_ID`, `ALERT_ID`, and `SIGNING_KEY` from your environment. `WAZUH_AUTH_HEADER` is a private file containing the API authorization header, and `WAZUH_CA` is the API's trusted CA certificate.

```sh
umask 077
work=$(mktemp -d)
all-os-openedr-response sign isolate --endpoint "$ENDPOINT_ID" --agent 001 \
  --alert "$ALERT_ID" --signer incident-operator --key "$SIGNING_KEY" \
  --seconds 120 > "$work/isolate.json"
curl --fail-with-body --cacert "$WAZUH_CA" --header "@$WAZUH_AUTH_HEADER" \
  --header 'Content-Type: application/json' --request PUT \
  --data-binary "@$work/isolate.json" "$WAZUH_API/active-response?agents_list=001"
```

Save the lease ID printed by the signer. The Wazuh API reports delivery to the active response queue. Look for `openedr_response_result: isolated` in rule `110104` before treating isolation as applied. Audit records include the signed operator, agent, alert, and lease IDs. An `authorized` record shows the endpoint accepted the approval. `isolated` and `released` record firewall changes. The deadline remains searchable even if the endpoint cannot report when the kernel lease ends.

To restore access early, repeat the sample with `sign release --lease LEASE_ID` in place of `sign isolate`, omit `--seconds`, and send the resulting body to the same agent. Use `sudo all-os-openedr-response local-release` from the endpoint console if the management path is unavailable. An older approval cannot change a later lease. The in-kernel timeout restores filtering behavior if the manager or Wazuh agent stops, and reboot clears the temporary rules. Avoid saving the response table into persistent firewall configuration. If local release is unavailable, an administrator can inspect `nft list table inet all_os_openedr_response` and delete that table after verifying the lease comment. [Wazuh Active Response API](https://documentation.wazuh.com/current/user-manual/api/reference.html) · [nftables element timeouts](https://netfilter.org/projects/nftables/manpage.html)

### Quarantine a managed executable from a Wazuh alert

To enable file quarantine, add `"quarantine": {"filesystem": "/srv/openedr-exec", "uuid": "VOLUME_UUID"}` to the endpoint's root-owned response configuration. Use the same dedicated ext4 execution volume and UUID as the managed launcher. On this volume the response accepts a root-owned ELF executable or shebang script up to 32 MiB with a single link, an administrator-controlled path, and ordinary execution permissions. The signed approval identifies the agent, endpoint, alert, volume, path relative to the mount, and expected SHA-256. Match the digest and relative path to the alert before signing.

```sh
all-os-openedr-response sign quarantine --endpoint "$ENDPOINT_ID" --agent 001 \
  --alert "$ALERT_ID" --signer incident-operator --key "$SIGNING_KEY" \
  --volume "$VOLUME_UUID" --path "$RELATIVE_EXECUTABLE" --sha256 "$FILE_SHA256" \
  > "$work/quarantine.json"
curl --fail-with-body --cacert "$WAZUH_CA" --header "@$WAZUH_AUTH_HEADER" \
  --header 'Content-Type: application/json' --request PUT \
  --data-binary "@$work/quarantine.json" "$WAZUH_API/active-response?agents_list=001"
```

Save the quarantine ID printed by the signer. The endpoint moves the verified inode into the root-only `.openedr-quarantine` directory on the same volume. The move preserves its ownership, permissions, and extended attributes. Look for `openedr_response_result: quarantined` under Wazuh rule `110125`. The action disables new launches through the original path and retains the file for investigation. Existing processes, open file descriptors, and other copies require their own response.

To restore after review, repeat the signing command with `sign restore --lease QUARANTINE_ID` and the original volume, relative path, and digest. A restore requires the matching receipt and refuses to overwrite an occupied destination, including a symlink. The file stays quarantined across a reboot and remains available to a root operator. If Wazuh is unavailable, use `sudo all-os-openedr-response local-restore --lease QUARANTINE_ID` from the endpoint console. The console command reads the original path and digest from the private receipt. Retain the receipts and the audit log according to site policy. [Linux atomic rename](https://manpages.debian.org/trixie/manpages-dev/renameat.2.en.html)

Use the current OpenSearch template for new indices, or add the keyword mappings for `data.openedr_response_file_sha256` and `data.openedr_response_volume_uuid` to the current dedicated index. The response audit records the digest, volume, quarantine ID, and Wazuh authorization fields. Restrict the signed dispatch body and local receipt to authorized operators because both include the original relative path.

### Stop an enrolled Debian process from a Wazuh alert

Add a `process_targets` map to the root-owned response configuration. Each key is an explicitly enrolled systemd service in `system.slice`. Its value is the numeric UID of the service's dedicated non-root account. For example, use `"process_targets": {"workload.service": 1200}` to enroll one service. Use cgroup v2, keep the service cgroup under administrator control, and set `NoNewPrivileges=yes` and an empty `CapabilityBoundingSet=` on the workload. The endpoint checks the target's real, effective, saved, and filesystem UIDs, capability sets, and live cgroup membership.

Use an alert with `openedr_file_attribution: pidfd_snapshot` from the file or executable collector. Take the PID, boot ID, and actor ID from `openedr_pid`, `openedr_boot_id`, and `openedr_file_actor_id`. Match the observed UID and the workload's service unit to the approved configuration before signing. The actor ID identifies a process lifetime across PID reuse and exec. Sign only after verifying the endpoint in Wazuh.

```sh
all-os-openedr-response sign terminate --endpoint "$ENDPOINT_ID" --agent 001 \
  --alert "$ALERT_ID" --signer incident-operator --key "$SIGNING_KEY" \
  --pid "$TARGET_PID" --uid "$TARGET_UID" --boot-id "$BOOT_ID" \
  --actor-id "$ACTOR_ID" --unit "$TARGET_UNIT" > "$work/terminate.json"
curl --fail-with-body --cacert "$WAZUH_CA" --header "@$WAZUH_AUTH_HEADER" \
  --header 'Content-Type: application/json' --request PUT \
  --data-binary "@$work/terminate.json" "$WAZUH_API/active-response?agents_list=001"
```

The endpoint rechecks the actor and enrollment, sends `SIGKILL` through the Linux process descriptor, and checks for exit. Check rule `110126` for `terminated`. A `termination_pending` receipt means the signal was sent and exit was still unconfirmed when the five-second check ended. The response sends one signal to the selected process. Systemd can stop remaining processes or start a replacement according to the service's policy. Use the normal service start procedure after reviewing the workload. [Linux process descriptors](https://manpages.debian.org/trixie/manpages-dev/pidfd_open.2.en.html) · [Linux no new privileges](https://docs.kernel.org/userspace-api/no_new_privs.html)

Use the current OpenSearch template for new indices or add the process response mappings to the current dedicated index. The receipts record the PID, UID, boot ID, actor ID, unit, source alert, and response ID.

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

Copy the signed APK to the target and install it as root. For a stable build, replace `VERSION` in the filename with its numeric version. For a nightly built from the preview source, pass the full release version to `build.sh` and install the emitted file. The nightly uses the UTC date as a prerelease suffix and the workflow run number as the APK package revision.

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

Nightly filenames and tags use `<version>-nightly.<UTC date>.r.<workflow run number>.g<commit>`. The run number orders builds from the same day, including when the commit hashes sort in reverse order. Rerunning the workflow keeps its original date, run number, and tag. Publication validates an existing tag against the build commit and verifies the published checksums before leaving the assets in place.

GitHub's repository Actions policy restricts workflow execution to the maintainer and permits only `push`, `pull_request_target`, `schedule`, and `workflow_dispatch`. Keep that policy active before enabling Actions. Maintainer updates and same-repository maintainer PRs from protected `codex/` or `release/` branches use `cormier-runners`. The PR workflow uses the base branch definition and checks out the exact head SHA after its identity checks pass. Contributors can run `sh scripts/check-preview.sh` in a local Linux environment and submit changes from their own forks. Keep the maintainer-only branch and stable tag rulesets active. Use Codex review on the exact PR revision before merging or publishing a stable release.

For stable publication, open the maintainer release PR against main. Verify the Codex summary reports a completed code review with no unresolved findings on the final PR head. Merge while the PR head and resulting release commit have the same tree. Update the maintainer branch `release/<version>` to that release commit, push the matching `v<version>` tag, and dispatch `Preview CI and release` on that branch with the stable channel.
