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

EVENT_FIELDS = (
    "openedr_source", "openedr_schema", "openedr_event", "openedr_event_id",
    "openedr_host", "openedr_observed_at", "openedr_pid", "openedr_process",
)
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

    def search(self, size):
        query = {
            "size": size,
            "_source": [f"data.{field}" for field in EVENT_FIELDS],
            "query": {"match_phrase": {"data.openedr_source": "all-os-openedr"}},
        }
        if size:
            query["sort"] = [{"timestamp": {"order": "desc", "unmapped_type": "date"}}]
        options = urlencode({"ignore_unavailable": "true", "allow_partial_search_results": "false"})
        request = Request(
            f"{self.base}/_search?{options}",
            data=json.dumps(query).encode(),
            headers={"Authorization": self.authorization, "Content-Type": "application/json"},
        )
        with self.client.open(request, timeout=3) as response:
            data = response.read(MAX_RESPONSE + 1)
        if len(data) > MAX_RESPONSE:
            raise ValueError("OpenSearch response exceeds size limit")
        records = []
        payload = json.loads(data)
        if payload.get("timed_out"):
            raise ValueError("OpenSearch search timed out")
        for hit in payload["hits"]["hits"]:
            event = hit["_source"].get("data", {})
            if event.get("openedr_source") == "all-os-openedr":
                records.append({field: event[field] for field in EVENT_FIELDS if field in event})
        return records


class Manager(BaseHTTPRequestHandler):
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
        if self.path not in ("/readyz", "/v1/events"):
            self.reply(404)
            return
        if self.path == "/v1/events":
            provided = self.headers.get("Authorization", "").encode("utf-8")
            if not hmac.compare_digest(provided, self.server.authorization):
                self.reply(401)
                return
        try:
            events = self.server.index.search(0 if self.path == "/readyz" else 25)
        except (OSError, URLError, KeyError, TypeError, ValueError):
            self.reply(503, {"status": "unavailable"})
            return
        self.reply(200, {"events": events} if self.path == "/v1/events" else {"status": "ready"})


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
