"""Follow kernel process lifetimes starting at a recorded containment launch."""

import re
import time


LAUNCH_FIELDS = (
    "openedr_source", "openedr_event", "openedr_host", "openedr_boot_id",
    "openedr_containment_launch_id", "openedr_containment_pid", "openedr_containment_monitor_pid",
    "openedr_containment_fork_after_ns", "openedr_containment_fork_before_ns",
)
PROCESS_FIELDS = (
    "openedr_source", "openedr_event", "openedr_event_id", "openedr_host", "openedr_boot_id",
    "openedr_stream_id", "openedr_observed_at", "openedr_kernel_monotonic_ns",
    "openedr_pid", "openedr_parent_pid", "openedr_process_id", "openedr_parent_process_id",
    "openedr_thread_group_leader", "openedr_wait_status",
)
PROCESS_ID = re.compile(r"[0-9a-f]{64}")
STREAM_ID = re.compile(r"[0-9a-f]{32}")
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
MAX_PROCESSES = 128
MAX_DEPTH = 8
MAX_EVENTS = 256
KERNEL_ORDER = [
    {"data.openedr_kernel_monotonic_ns": {"order": "asc", "unmapped_type": "long"}},
    {"data.openedr_event_id": {"order": "asc", "unmapped_type": "keyword"}},
]


def positive_integer(value):
    if isinstance(value, str):
        # Wazuh renders larger JSON integers as fixed-point strings.
        number = re.fullmatch(r"([0-9]{1,19})(?:\.0{1,8})?", value)
        value = int(number[1]) if number is not None else None
    return value if type(value) is int and 0 < value < 2**63 else None


def containment_process_tree(index, launch_id):
    deadline = time.monotonic() + 3

    def search(size, fields, exact, filters=(), *, ordered=False):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Process tree search expired")
        query = {
            "size": size,
            "_source": ["agent.id", *(f"data.{field}" for field in fields)],
            "query": {"bool": {"filter": [
                {"term": {"data.openedr_source": "all-os-openedr"}},
                *({"term": {field: value}} for field, value in exact.items()),
                *filters,
            ]}},
        }
        if ordered:
            query["sort"] = KERNEL_ORDER
        return index.execute(query, timeout=remaining)

    result = {"launch_id": launch_id, "root_process_id": None, "processes": [], "events": [], "truncated": False}
    creation = search(2, LAUNCH_FIELDS, {
        "data.openedr_containment_launch_id": launch_id,
        "data.openedr_event": "executable.sandbox_created",
    })
    if len(creation) != 1:
        return {**result, "status": "ambiguous_launch" if creation else "creation_unavailable"}
    event = creation[0].get("data", {})
    agent = creation[0].get("agent", {}).get("id")
    host, boot = event.get("openedr_host"), event.get("openedr_boot_id")
    supervisor = positive_integer(event.get("openedr_containment_pid"))
    monitor = positive_integer(event.get("openedr_containment_monitor_pid"))
    after = positive_integer(event.get("openedr_containment_fork_after_ns"))
    before = positive_integer(event.get("openedr_containment_fork_before_ns"))
    if (event.get("openedr_containment_launch_id") != launch_id
            or event.get("openedr_event") != "executable.sandbox_created"
            or not isinstance(agent, str) or not re.fullmatch(r"[0-9]{1,16}", agent)
            or not isinstance(host, str) or not 0 < len(host) <= 256
            or not isinstance(boot, str) or not BOOT_ID.fullmatch(boot)
            or None in (supervisor, monitor, after, before) or before < after):
        return {**result, "status": "anchor_unavailable"}

    scope = {"agent.id": agent, "data.openedr_host": host, "data.openedr_boot_id": boot}
    fork_scope = {**scope, "data.openedr_event": "process.fork", "data.openedr_thread_group_leader": True}
    roots = search(2, PROCESS_FIELDS, {
        **fork_scope, "data.openedr_pid": supervisor, "data.openedr_parent_pid": monitor,
    }, [{"range": {"data.openedr_kernel_monotonic_ns": {"gte": after, "lte": before}}}])
    if len(roots) != 1:
        return {**result, "status": "ambiguous_root" if roots else "root_unavailable"}
    root = roots[0].get("data", {})
    root_id = root.get("openedr_process_id")
    stream = root.get("openedr_stream_id")
    stamp = positive_integer(root.get("openedr_kernel_monotonic_ns"))
    if (not isinstance(root_id, str) or not PROCESS_ID.fullmatch(root_id)
            or not isinstance(stream, str) or not STREAM_ID.fullmatch(stream)
            or roots[0].get("agent", {}).get("id") != agent
            or root.get("openedr_boot_id") != boot or root.get("openedr_host") != host
            or positive_integer(root.get("openedr_pid")) != supervisor
            or positive_integer(root.get("openedr_parent_pid")) != monitor
            or stamp is None or not after <= stamp <= before):
        return {**result, "status": "root_unavailable"}

    fork_scope["data.openedr_stream_id"] = stream
    scope["data.openedr_stream_id"] = stream
    nodes = {root_id: root}
    frontier = [root_id]
    truncated = False
    for _ in range(MAX_DEPTH):
        remaining = MAX_PROCESSES - len(nodes)
        children = search(remaining + 1, PROCESS_FIELDS, fork_scope, [
            {"terms": {"data.openedr_parent_process_id": frontier}},
        ], ordered=True)
        truncated = len(children) > remaining
        next_frontier = []
        for hit in children[:remaining]:
            child = hit.get("data", {})
            node_id = child.get("openedr_process_id")
            if (isinstance(node_id, str) and PROCESS_ID.fullmatch(node_id) and node_id not in nodes
                    and child.get("openedr_parent_process_id") in frontier):
                nodes[node_id] = child
                next_frontier.append(node_id)
        if truncated or not next_frontier:
            break
        frontier = next_frontier
    else:
        truncated = True

    events = search(MAX_EVENTS + 1, PROCESS_FIELDS, scope, [
        {"terms": {"data.openedr_process_id": list(nodes)}},
        {"terms": {"data.openedr_event": ["process.exec", "process.task_exit"]}},
    ], ordered=True)
    return {
        **result, "status": "observed", "root_process_id": root_id,
        "truncated": truncated or len(events) > MAX_EVENTS,
        "processes": [{field: node[field] for field in PROCESS_FIELDS if field in node} for node in nodes.values()],
        "events": [
            {field: event[field] for field in PROCESS_FIELDS if field in event}
            for hit in events[:MAX_EVENTS] if (event := hit.get("data", {})).get("openedr_process_id") in nodes
        ],
    }
