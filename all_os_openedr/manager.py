"""Read-only API for reviewing OpenEDR observations indexed by Wazuh."""

import base64
import hmac
import json
import os
import re
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from .process_tree import BOOT_ID, KERNEL_ORDER, containment_process_tree, positive_integer

EVENT_FIELDS = (
    "openedr_source", "openedr_schema", "openedr_event", "openedr_event_id",
    "openedr_host", "openedr_observed_at", "openedr_pid", "openedr_process",
)
CONTAINMENT_FIELDS = EVENT_FIELDS + (
    "openedr_boot_id", "openedr_requester_uid", "openedr_executable_sha256",
    "openedr_executable_verdict", "openedr_containment_application",
    "openedr_containment_launch_id", "openedr_containment_pid",
    "openedr_containment_pid_namespace", "openedr_containment_decision",
    "openedr_containment_reason", "openedr_containment_exit_code", "openedr_containment_audit_session",
)
ACTIVITY_FIELDS = EVENT_FIELDS + (
    "openedr_kernel_monotonic_ns", "openedr_containment_activity_class",
    "openedr_containment_activity_operation", "openedr_containment_activity_result",
    "openedr_containment_activity_errno",
)
CONTAINMENT_EVENTS = ("executable.sandbox_created", "executable.launch_decision")
CONTAINMENT_ROUTE = re.compile(r"/v1/containment/([0-9a-f]{32})")
PROCESSES_ROUTE = re.compile(r"/v1/containment/([0-9a-f]{32})/processes")
ACTIVITY_ROUTE = re.compile(r"/v1/containment/([0-9a-f]{32})/activity")
MAX_ACTIVITY = 128
MAX_RESPONSE = 1024 * 1024


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


class Index:
    def __init__(self):
        url = urlsplit(os.environ["OPENSEARCH_URL"])
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.path not in ("", "/") or url.query or url.fragment):
            raise ValueError("OPENSEARCH_URL must be an HTTPS origin")
        prefix = os.environ.get("OPENSEARCH_INDEX_PREFIX", "openedr-alerts-v1")
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,95}", prefix):
            raise ValueError("Invalid OpenSearch index prefix")
        credentials = os.environ["OPENSEARCH_USERNAME"] + ":" + os.environ["OPENSEARCH_PASSWORD"]
        self.authorization = "Basic " + base64.b64encode(credentials.encode()).decode()
        self.base = f"https://{url.netloc}/{prefix}-*"
        context = ssl.create_default_context(cafile=os.environ.get("OPENSEARCH_CA_FILE"))
        self.client = build_opener(ProxyHandler({}), NoRedirects(), HTTPSHandler(context=context))

    def search(self, size, *, launch_id=None):
        fields = EVENT_FIELDS if launch_id is None else CONTAINMENT_FIELDS
        query = {
            "size": size,
            "_source": [f"data.{field}" for field in fields],
            "query": {"match_phrase": {"data.openedr_source": "all-os-openedr"}},
        }
        if launch_id is not None:
            query["query"] = {"bool": {"filter": [
                query["query"],
                {"term": {"data.openedr_containment_launch_id": launch_id}},
                {"terms": {"data.openedr_event": CONTAINMENT_EVENTS}},
            ]}}
            query["sort"] = [
                {"data.openedr_observed_at": {"order": "asc", "unmapped_type": "date"}},
                {"data.openedr_event": {"order": "desc", "unmapped_type": "keyword"}},
            ]
        elif size:
            query["sort"] = [{"timestamp": {"order": "desc", "unmapped_type": "date"}}]
        records = []
        for source in self.execute(query):
            event = source.get("data", {})
            if event.get("openedr_source") != "all-os-openedr":
                continue
            if launch_id is not None and (event.get("openedr_containment_launch_id") != launch_id
                                          or event.get("openedr_event") not in CONTAINMENT_EVENTS):
                continue
            records.append({field: event[field] for field in fields if field in event})
        return records

    def execute(self, query, *, timeout=3):
        options = urlencode({"ignore_unavailable": "true", "allow_partial_search_results": "false"})
        request = Request(
            f"{self.base}/_search?{options}",
            data=json.dumps(query).encode(),
            headers={"Authorization": self.authorization, "Content-Type": "application/json"},
        )
        with self.client.open(request, timeout=timeout) as response:
            data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValueError("OpenSearch response exceeds size limit")
        payload = json.loads(data)
        if payload.get("timed_out"):
            raise ValueError("OpenSearch search timed out")
        return [hit["_source"] for hit in payload["hits"]["hits"]]

    def containment_activity(self, launch_id):
        result = {"launch_id": launch_id, "events": [], "truncated": False}
        session_field = "openedr_containment_audit_session"

        def search(fields, terms, size, ordered=False):
            query = {
                "_source": ["agent.id", *(f"data.{field}" for field in fields)],
                "size": size,
                "query": {"bool": {"filter": [
                    {"term": {"data.openedr_source": "all-os-openedr"}},
                    *({"term": {field: value}} for field, value in terms.items()),
                ]}},
            }
            if ordered:
                query["sort"] = KERNEL_ORDER
            return self.execute(query)

        records = search(("openedr_host", "openedr_boot_id", "openedr_uid", session_field), {
            "data.openedr_event": "executable.sandbox_created",
            "data.openedr_containment_launch_id": launch_id,
        }, 2)
        if len(records) != 1:
            return {**result, "status": "ambiguous_launch" if records else "creation_unavailable"}
        creation = records[0].get("data", {})
        agent = records[0].get("agent", {}).get("id")
        host, boot = creation.get("openedr_host"), creation.get("openedr_boot_id")
        uid = positive_integer(creation.get("openedr_uid"))
        session = creation.get(session_field)
        session = 0 if type(session) in (int, str) and session in (0, "0") else positive_integer(session)
        if (session is None or session >= 2**32 - 1 or uid is None or uid >= 2**32 - 1
                or not isinstance(agent, str) or not re.fullmatch(r"[0-9]{1,16}", agent)
                or not isinstance(host, str) or not 0 < len(host) <= 256
                or not isinstance(boot, str) or not BOOT_ID.fullmatch(boot)):
            return {**result, "status": "audit_session_unavailable"}
        hits = search(ACTIVITY_FIELDS, {
            "agent.id": agent, "data.openedr_host": host, "data.openedr_boot_id": boot,
            "data.openedr_uid": uid, f"data.{session_field}": session,
            "data.openedr_event": "executable.sandbox_activity",
        }, MAX_ACTIVITY + 1, ordered=True)
        events = [hit.get("data", {}) for hit in hits]
        limited = any(event.get("openedr_containment_activity_result") == "limit_reached" for event in events)
        return {
            **result, "status": "observed" if events else "activity_unavailable",
            "truncated": limited or len(events) > MAX_ACTIVITY,
            "events": [
                {field: event[field] for field in ACTIVITY_FIELDS if field in event}
                for event in events if event.get("openedr_containment_activity_result") != "limit_reached"
            ][:MAX_ACTIVITY],
        }


class Manager(BaseHTTPRequestHandler):
    timeout = 5

    def log_message(self, format, *args):
        # Request paths and client-controlled values may contain sensitive data.
        pass

    def reply(self, status, payload=None):
        content = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        if content:
            self.wfile.write(content)

    def do_GET(self):
        if self.path == "/healthz":
            self.reply(200, {"status": "ok"})
            return
        containment = CONTAINMENT_ROUTE.fullmatch(self.path)
        processes = PROCESSES_ROUTE.fullmatch(self.path)
        activity = ACTIVITY_ROUTE.fullmatch(self.path)
        if self.path not in ("/readyz", "/v1/events") and not (containment or processes or activity):
            self.reply(404)
            return
        ready = self.path == "/readyz"
        if not ready:
            provided = self.headers.get("Authorization", "").encode("utf-8")
            if not hmac.compare_digest(provided, self.server.authorization):
                self.reply(401)
                return
        try:
            if activity is not None:
                payload = self.server.index.containment_activity(activity[1])
            elif processes is not None:
                payload = containment_process_tree(self.server.index, processes[1])
            elif containment is not None:
                payload = {"events": self.server.index.search(4, launch_id=containment[1])}
            else:
                events = self.server.index.search(0 if ready else 25)
                payload = {"status": "ready"} if ready else {"events": events}
        except (AttributeError, OSError, URLError, KeyError, TypeError, ValueError):
            self.reply(503, {"status": "unavailable"})
            return
        self.reply(200, payload)


def main():
    token = Path(os.environ["MANAGER_TOKEN_FILE"]).read_bytes().strip()
    if len(token) < 32 or any(byte < 33 or byte > 126 for byte in token):
        raise ValueError("Provide an ASCII management token of at least 32 characters")
    index = Index()
    with ThreadingHTTPServer(("0.0.0.0", 8080), Manager) as server:
        server.authorization = b"Bearer " + token
        server.index = index
        server.serve_forever()


if __name__ == "__main__":
    main()
