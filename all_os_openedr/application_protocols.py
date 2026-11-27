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
HOSTNAME = re.compile(r"[A-Za-z0-9._-]{1,253}")
FTP_COMMAND = re.compile(rb"([A-Za-z]{3,4})(?: ([^\r\n]*))?")
FTP_REPLY = re.compile(rb"([1-5][0-9]{2})([ -])(.*)")


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
    if target.startswith("//"):
        return None
    if target.startswith("/"):
        path = target.split("?", 1)[0].split("#", 1)[0]
    elif target.startswith("http://"):
        parts = urlsplit(target)
        # An absolute request may carry userinfo. Retain only the host and path.
        server = parts.netloc.rsplit("@", 1)[-1]
        host = authority(server.encode("ascii"))
        path = parts.path or "/"
    else:
        return None
    path = "/".join(segment.split(";", 1)[0] for segment in path.split("/"))
    if not path or len(path) > PATH_LIMIT:
        return None
    return {"openedr_request_path": path, **({"openedr_request_host": host} if host else {})}


class HTTPRequests:
    def __init__(self):
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

    def skip(self, incoming, length):
        if self.state != "opaque":
            self.consume(length)

    def headers(self, value):
        request, _, fields = value.partition(b"\r\n")
        match = REQUEST.fullmatch(request)
        if not match or not TOKEN.fullmatch(match[1]):
            raise ValueError("Invalid HTTP request line")
        method, target = match.groups()
        length, transfer, host, upgraded = None, None, None, False
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
                    upgraded = True
        if transfer is not None and (
            length is not None or transfer[-1] != b"chunked" or transfer.count(b"chunked") != 1 or not all(transfer)
        ):
            raise ValueError("Unsupported HTTP body framing")
        if method == b"CONNECT" or upgraded:
            self.state = "opaque"
        elif transfer is not None:
            self.state = "chunk_size"
        elif length:
            self.state = "body"
            self.remaining = length
        if method in {b"GET", b"POST"} and (fields := request_target(target, host)):
            return {"openedr_application_protocol": "http", "openedr_request_method": method.decode("ascii"), **fields}
        return None

    def feed(self, incoming, data):
        if incoming or self.state == "opaque":
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


def ftp_path(value, cwd=None):
    if not value or len(value) > PATH_LIMIT or b"://" in value or any(byte < 32 or byte == 127 for byte in value):
        return None
    path = value.decode("utf-8", errors="backslashreplace")
    if path.startswith("/"):
        return posixpath.normpath(path)
    return posixpath.normpath(posixpath.join(cwd, path)) if cwd else path


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
        if command == b"AUTH":
            self.opaque = True
            self.pending.clear()
            return None
        if len(self.pending) >= 64:
            raise ValueError("FTP command queue exceeds the observation bound")
        if command in {b"CWD", b"XCWD", b"CDUP", b"XCUP", b"PWD", b"XPWD", b"REIN"}:
            path = argument if command in {b"CWD", b"XCWD"} and len(argument) <= PATH_LIMIT else b""
            self.pending.append((command, path))
        else:
            self.pending.append((b"", b""))
        if command == b"RETR":
            changing = any(c in {b"CWD", b"XCWD", b"CDUP", b"XCUP", b"REIN"} for c, _ in self.pending)
            path = ftp_path(argument, None if changing else self.cwd)
            if path is not None:
                return {"openedr_application_protocol": "ftp", "openedr_request_method": "RETR",
                        "openedr_request_path": path, "openedr_request_path_scope": "absolute" if path.startswith("/") else "relative"}
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
            if not code.startswith(b"2"):
                return
            if command in {b"CWD", b"XCWD"}:
                new = ftp_path(argument, self.cwd)
                self.cwd = new if new and new.startswith("/") else None
            elif command in {b"CDUP", b"XCUP"} and self.cwd:
                self.cwd = posixpath.dirname(self.cwd)
            elif command in {b"PWD", b"XPWD"} and code == b"257":
                path = re.match(rb'"((?:[^"]|"")*)"', message)
                new = ftp_path(path[1].replace(b'""', b'"')) if path else None
                self.cwd = new if new and new.startswith("/") else None
            elif command == b"REIN":
                self.cwd = None

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
