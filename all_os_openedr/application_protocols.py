"""Bounded parsers for outbound cleartext HTTP requests and FTP retrievals."""

import ipaddress
import posixpath
import re
from collections import deque
from urllib.parse import urlsplit


HEADER_LIMIT = 8192
LINE_LIMIT = 4096
PATH_LIMIT = 1024
TOKEN = re.compile(rb"[!#$%&'*+\-.^_\x60|~0-9a-zA-Z]+")
REQUEST = re.compile(rb"([^ ]+) ([!-~]+) HTTP/1\.[01]")
RESPONSE = re.compile(rb"HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?")
HOSTNAME = re.compile(r"[A-Za-z0-9._-]{1,253}")
FTP_COMMAND = re.compile(rb"([A-Za-z]{3,4})(?: ([^\r\n]*))?")
FTP_REPLY = re.compile(rb"([1-5][0-9]{2})([ -])(.*)")
FTP_DIRECTORY_CHANGES = {b"CWD", b"XCWD", b"CDUP", b"XCUP"}
FTP_SESSION_CHANGES = {b"USER", b"PASS", b"ACCT", b"REIN"}
FTP_CONTEXT_COMMANDS = FTP_DIRECTORY_CHANGES | FTP_SESSION_CHANGES | {b"PWD", b"XPWD", b"AUTH"}


def authority(value):
    if not value or any(byte <= 32 or byte >= 127 for byte in value):
        return None
    text = value.decode("ascii")
    try:
        part = urlsplit("//" + text)
        if part.netloc != text or part.username is not None or part.port == 0:
            return None
        name = part.hostname
        if name is None:
            return None
        if HOSTNAME.fullmatch(name):
            return name
        return str(ipaddress.ip_address(name))
    except ValueError:
        return None


def request_target(raw, host):
    target = raw.decode("ascii")
    if target.startswith("/"):
        # HTTP origin-form permits consecutive slashes in the path.
        path = target.split("?", 1)[0].split("#", 1)[0]
    else:
        parts = urlsplit(target)
        if parts.scheme.lower() != "http" or not parts.netloc:
            return None
        # An absolute request may carry userinfo. Retain only the host and path.
        server = parts.netloc.rsplit("@", 1)[-1]
        host = authority(server.encode("ascii"))
        path = parts.path or "/"
    path = "/".join(segment.split(";", 1)[0] for segment in path.split("/"))
    if not path or len(path) > PATH_LIMIT:
        return None
    return {"openedr_request_path": path, **({"openedr_request_host": host} if host else {})}


def upgrade_protocols(values):
    if len(values) > 32:
        return frozenset()
    protocols = set()
    for value in values:
        name, slash, version = value.partition(b"/")
        if len(value) > 128 or not TOKEN.fullmatch(name) or (slash and not TOKEN.fullmatch(version)):
            return frozenset()
        protocols.add(name.lower() + slash + version)
    return frozenset(protocols)


def http_fields(fields):
    length, transfer, host = None, None, None
    upgrades = []
    connection_upgrade = False
    for field in fields.split(b"\r\n") if fields else ():
        name, separator, content = field.partition(b":")
        if not separator or not TOKEN.fullmatch(name):
            raise ValueError("Invalid HTTP header")
        content = content.strip(b" \t")
        match name.lower():
            case b"host":
                host = authority(content)
            case b"content-length":
                if not content.isdigit() or len(content) > 18 or length is not None:
                    raise ValueError("Invalid HTTP Content-Length")
                length = int(content)
            case b"transfer-encoding":
                if transfer is not None:
                    raise ValueError("Ambiguous HTTP transfer coding")
                transfer = [coding.strip() for coding in content.lower().split(b",")]
            case b"upgrade":
                upgrades.extend(value for item in content.split(b",") if (value := item.strip(b" \t")))
            case b"connection":
                connection_upgrade |= any(value.strip(b" \t").lower() == b"upgrade" for value in content.split(b","))
    if transfer is not None and (
        length is not None or transfer[-1] != b"chunked" or transfer.count(b"chunked") != 1 or not all(transfer)
    ):
        raise ValueError("Unsupported HTTP body framing")
    return length, transfer, host, upgrade_protocols(upgrades) if connection_upgrade else frozenset()


class HTTPStream:
    def __init__(self, headers):
        self.headers = headers
        self.buffer = bytearray()
        self.state = "headers"
        self.remaining = 0
        self.trailer_bytes = 0

    def consume(self, length):
        if length > self.remaining:
            raise ValueError("HTTP body boundary was not observed")
        self.remaining -= length
        if not self.remaining:
            self.state = "headers" if self.state == "body" else "chunk_end"

    def skip(self, length):
        if self.state != "opaque":
            self.consume(length)

    def body(self, length, transfer, close_delimited=False):
        if transfer is not None:
            self.state = "chunk_size"
        elif length:
            self.state = "body"
            self.remaining = length
        elif length is None and close_delimited:
            self.stop()

    def stop(self):
        self.state = "opaque"
        self.buffer.clear()

    def feed(self, data):
        if self.state == "opaque":
            return
        self.buffer.extend(data)
        while self.buffer:
            if self.state == "opaque":
                self.buffer.clear()
                return
            if self.state in {"body", "chunk_body"}:
                size = min(self.remaining, len(self.buffer))
                self.consume(size)
                del self.buffer[:size]
                continue
            if self.state == "chunk_end":
                if len(self.buffer) < 2:
                    return
                if self.buffer[:2] != b"\r\n":
                    raise ValueError("Invalid HTTP chunk boundary")
                del self.buffer[:2]
                self.state = "chunk_size"
                continue
            separator = b"\r\n\r\n" if self.state == "headers" else b"\r\n"
            limit = HEADER_LIMIT if self.state == "headers" else LINE_LIMIT
            end = self.buffer.find(separator)
            if end < 0 and len(self.buffer) <= limit:
                return
            if end < 0 or end + len(separator) > limit:
                raise ValueError("HTTP metadata exceeds the observation bound")
            line = bytes(self.buffer[:end])
            del self.buffer[:end + len(separator)]
            if self.state == "headers":
                if event := self.headers(line):
                    yield event
            elif self.state == "chunk_size":
                size = line.partition(b";")[0]
                if not re.fullmatch(rb"[a-fA-F0-9]{1,16}", size):
                    raise ValueError("Invalid HTTP chunk length")
                self.remaining = int(size, 16)
                self.state = "chunk_body" if self.remaining else "trailers"
                self.trailer_bytes = 0
            else:
                self.trailer_bytes += len(line) + 2
                if self.trailer_bytes > HEADER_LIMIT:
                    raise ValueError("HTTP trailers exceed the observation bound")
                if not line:
                    self.state = "headers"


class HTTPRequests:
    def __init__(self):
        self.pending = deque()
        self.streams = (HTTPStream(self.request), HTTPStream(self.response))

    def skip(self, incoming, length):
        self.streams[incoming].skip(length)

    def feed(self, incoming, data):
        yield from self.streams[incoming].feed(data)

    def request(self, value):
        first, _, headers = value.partition(b"\r\n")
        match = REQUEST.fullmatch(first)
        if not match or not TOKEN.fullmatch(match[1]):
            raise ValueError("Invalid HTTP request line")
        method, target = match.groups()
        length, transfer, host, offered_upgrade = http_fields(headers)
        if len(self.pending) >= 64:
            raise ValueError("HTTP request queue exceeds the observation bound")
        self.pending.append((method, offered_upgrade if first.endswith(b" HTTP/1.1") else frozenset()))
        self.streams[0].body(length, transfer)
        if method in {b"GET", b"POST"}:
            fields = request_target(target, host) or {"openedr_request_path_scope": "unavailable"}
            return {"openedr_application_protocol": "http", "openedr_request_method": method.decode("ascii"), **fields}
        return None

    def response(self, value):
        first, _, headers = value.partition(b"\r\n")
        match = RESPONSE.fullmatch(first)
        if not match or not self.pending:
            raise ValueError("Unmatched HTTP response")
        status = int(match[1])
        if status < 200 and status != 101:
            return None
        method, offered_upgrade = self.pending.popleft()
        if status == 101:
            selected = http_fields(headers)[3]
            if not first.startswith(b"HTTP/1.1 ") or not selected or not selected <= offered_upgrade:
                raise ValueError("Unmatched HTTP upgrade")
        if status == 101 or (method == b"CONNECT" and 200 <= status < 300):
            for stream in self.streams:
                stream.stop()
            self.pending.clear()
        elif method != b"HEAD" and status not in {204, 304}:
            length, transfer, _, _ = http_fields(headers)
            self.streams[1].body(length, transfer, close_delimited=True)
        return None


def ftp_path(value, cwd=None):
    if not value or len(value) > PATH_LIMIT or b"://" in value or any(byte < 32 or byte == 127 for byte in value):
        return None
    path = value.decode("utf-8", errors="backslashreplace")
    if len(path.encode("utf-8")) > PATH_LIMIT:
        return None
    if path.startswith("/") or not cwd:
        return path
    combined = posixpath.join(cwd, path)
    return combined if len(combined.encode("utf-8")) <= PATH_LIMIT else path


class FTPRequests:
    def __init__(self):
        self.buffers = (bytearray(), bytearray())
        self.pending = deque()
        self.cwd = None
        self.multiline = None
        self.greeted = False
        self.opaque = False

    def skip(self, incoming, length):
        if not self.opaque:
            raise ValueError("FTP control line was not fully observed")

    def command(self, line):
        match = FTP_COMMAND.fullmatch(line)
        if not match:
            raise ValueError("Invalid FTP command line")
        command, argument = match[1].upper(), match[2] or b""
        if len(self.pending) >= 64:
            raise ValueError("FTP command queue exceeds the observation bound")
        if command in FTP_CONTEXT_COMMANDS:
            path = argument if command in {b"CWD", b"XCWD"} and len(argument) <= PATH_LIMIT else b""
            self.pending.append((command, path))
        else:
            self.pending.append((b"", b""))
        if command == b"RETR":
            changing = any(c in FTP_DIRECTORY_CHANGES or c in FTP_SESSION_CHANGES for c, _ in self.pending)
            path = ftp_path(argument, None if changing else self.cwd)
            fields = {"openedr_application_protocol": "ftp", "openedr_request_method": "RETR"}
            if path is None:
                fields["openedr_request_path_scope"] = "unavailable"
            else:
                fields["openedr_request_path"] = path
                fields["openedr_request_path_scope"] = "absolute" if path.startswith("/") else "relative"
            return fields
        return None

    def reply(self, line):
        match = FTP_REPLY.fullmatch(line)
        if self.multiline is not None:
            if not match or match[1] != self.multiline or match[2] != b" ":
                return
            self.multiline = None
        elif not match:
            raise ValueError("Invalid FTP reply line")
        elif match[2] == b"-":
            self.multiline = match[1]
            return
        code, message = match[1], match[3]
        if code.startswith(b"1"):
            return
        if not self.greeted and code == b"220":
            self.greeted = True
            return
        if self.pending:
            command, argument = self.pending.popleft()
            if command in FTP_SESSION_CHANGES:
                self.cwd = None
            if not code.startswith(b"2"):
                return
            if command == b"AUTH" and code == b"234":
                self.opaque = True
                self.pending.clear()
            elif command in {b"CWD", b"XCWD"} and code == b"250":
                new = ftp_path(argument, self.cwd)
                self.cwd = new if new and new.startswith("/") else None
            elif command in {b"CDUP", b"XCUP"} and code in {b"200", b"250"}:
                self.cwd = None
            elif command in {b"PWD", b"XPWD"} and code == b"257":
                path = re.match(rb'"((?:[^"]|"")*)"', message)
                new = ftp_path(path[1].replace(b'""', b'"')) if path else None
                self.cwd = new if new and new.startswith("/") else None

    def feed(self, incoming, data):
        if self.opaque:
            return
        buffer = self.buffers[incoming]
        buffer.extend(data)
        while buffer:
            end = buffer.find(b"\r\n")
            if end < 0 and len(buffer) <= LINE_LIMIT:
                return
            if end < 0 or end + 2 > LINE_LIMIT:
                raise ValueError("FTP line exceeds the observation bound")
            line = bytes(buffer[:end])
            del buffer[:end + 2]
            if incoming:
                self.reply(line)
            elif event := self.command(line):
                yield event
            if self.opaque:
                for pending in self.buffers:
                    pending.clear()
                return
