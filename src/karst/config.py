"""Strict bootstrap configuration, deliberately separate from the full RunSpec."""

from dataclasses import asdict, dataclass
import ipaddress
import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit


class KarstError(Exception):
    """An actionable, credential-free failure."""


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise KarstError("duplicate JSON key")
        result[key] = value
    return result


def strict_json(raw):
    if len(raw) > 262144:
        raise KarstError("JSON exceeds 256 KiB")
    try:
        result = json.loads(raw, object_pairs_hook=_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(KarstError("non-finite JSON")))
        json.dumps(result, ensure_ascii=False).encode("utf-8", errors="strict")
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise KarstError("invalid JSON or Unicode") from exc


def exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise KarstError("missing or unsupported configuration fields")


def positive(value, maximum):
    if type(value) is not int or not 1 <= value <= maximum:
        raise KarstError("integer limit out of range")
    return value


def parse_url(value):
    if not isinstance(value, str) or len(value) > 8192:
        raise KarstError("invalid URL")
    if any(ord(c) < 33 or ord(c) > 126 for c in value) or "\\" in value:
        raise KarstError("URL must use unambiguous ASCII encoding")
    try:
        p = urlsplit(value)
        if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None or p.fragment:
            raise KarstError("unsupported URL scheme, credentials or fragment")
        port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
        host = p.hostname.lower()
        if not re.fullmatch(r"[a-z0-9.:-]+", host) or host.endswith("."):
            raise KarstError("unsupported hostname")
        if not 1 <= port <= 65535:
            raise KarstError("invalid port")
        path = p.path or "/"
        decoded = unquote(path, errors="strict")
        # Reject ambiguous segment encodings instead of guessing server normalization.
        if re.search(r"%(?![0-9a-fA-F]{2})", path) or "%" in decoded or "\\" in decoded:
            raise KarstError("ambiguous path encoding")
        if any(c in decoded for c in ("\x00", "\r", "\n", "\t")) or any(s in (".", "..") for s in decoded.split("/")):
            raise KarstError("ambiguous path")
        if re.search(r"%2f|%5c", path, re.I) or "//" in path:
            raise KarstError("ambiguous path separators")
        netloc = f"[{host}]" if ":" in host else host
        if port != (443 if p.scheme == "https" else 80):
            netloc += f":{port}"
        origin = f"{p.scheme}://{netloc}"
        canonical = urlunsplit((p.scheme, netloc, path, p.query, ""))
        return canonical, origin, host, port, decoded
    except (ValueError, UnicodeError) as exc:
        raise KarstError("invalid URL") from exc


@dataclass(frozen=True)
class Origin:
    origin: str
    path_prefixes: tuple[str, ...]


@dataclass(frozen=True)
class Identity:
    name: str
    origin: str
    bearer_env: str


@dataclass(frozen=True)
class Limits:
    max_requests: int
    max_response_bytes: int
    max_total_response_bytes: int
    timeout_seconds: int
    wall_seconds: int
    max_redirects: int


@dataclass(frozen=True)
class ProbeConfig:
    profile: str
    entrypoints: tuple[str, ...]
    origins: tuple[Origin, ...]
    allowed_cidrs: tuple[str, ...]
    denied_cidrs: tuple[str, ...]
    identities: tuple[Identity, ...]
    limits: Limits

    def snapshot(self):
        return asdict(self)

    def check_url(self, url):
        parsed = parse_url(url)
        _, origin, _, _, path = parsed
        for rule in self.origins:
            if rule.origin == origin and any(prefix == "/" or path == prefix or path.startswith(prefix + "/") for prefix in rule.path_prefixes):
                return parsed
        raise KarstError("scope_denied")

    def allows_ip(self, value):
        addr = ipaddress.ip_address(value)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return (any(addr in ipaddress.ip_network(n) for n in self.allowed_cidrs)
                and not any(addr in ipaddress.ip_network(n) for n in self.denied_cidrs))


def load_config(path):
    try:
        raw = Path(path).read_bytes()
        data = strict_json(raw.decode("utf-8"))
    except (OSError, UnicodeError) as exc:
        raise KarstError("configuration is not readable UTF-8") from exc
    return parse_config(data)


def parse_config(data):
    """Validate the legacy transport shape; also used by the I0 adapter."""
    exact(data, ("profile", "entrypoints", "origins", "allowed_cidrs", "denied_cidrs", "identities", "limits"))
    if data["profile"] != "karst-http-probe/1":
        raise KarstError("unsupported profile; design examples are not executable configs")
    for name in ("entrypoints", "origins", "allowed_cidrs", "denied_cidrs", "identities"):
        if not isinstance(data[name], list) or len(data[name]) > 32:
            raise KarstError("invalid configuration list")
    if not data["entrypoints"] or not data["origins"] or not data["allowed_cidrs"]:
        raise KarstError("entrypoints and explicit Web/network scope are required")
    origins = []
    for item in data["origins"]:
        exact(item, ("origin", "path_prefixes"))
        parsed = parse_url(item["origin"])
        if item["origin"] != parsed[1]:
            raise KarstError("origin must contain only scheme, host and optional port")
        prefixes = item["path_prefixes"]
        if not isinstance(prefixes, list) or not prefixes or len(prefixes) > 32:
            raise KarstError("invalid path prefixes")
        for prefix in prefixes:
            if not isinstance(prefix, str) or not prefix.startswith("/") or "?" in prefix or (prefix != "/" and prefix.endswith("/")):
                raise KarstError("invalid path prefix")
            if parse_url(item["origin"] + prefix)[4] != prefix:
                raise KarstError("prefix must be decoded")
        origins.append(Origin(item["origin"], tuple(prefixes)))
    networks = {}
    for name in ("allowed_cidrs", "denied_cidrs"):
        try:
            networks[name] = tuple(str(ipaddress.ip_network(n, strict=True)) for n in data[name])
        except (ValueError, TypeError) as exc:
            raise KarstError("invalid explicit network range") from exc
    identities = []
    names = {"anonymous"}
    for item in data["identities"]:
        exact(item, ("name", "origin", "bearer_env"))
        if not isinstance(item["name"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,48}", item["name"]) or item["name"] in names:
            raise KarstError("invalid or duplicate identity name")
        if not isinstance(item["origin"], str) or item["origin"] not in {x.origin for x in origins} or not isinstance(item["bearer_env"], str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{0,99}", item["bearer_env"]):
            raise KarstError("invalid identity origin or credential reference")
        names.add(item["name"])
        identities.append(Identity(**item))
    limits = data["limits"]
    exact(limits, Limits.__dataclass_fields__)
    for name, maximum in {"max_requests": 1000, "max_response_bytes": 4*1024*1024,
                          "max_total_response_bytes": 64*1024*1024, "timeout_seconds": 60,
                          "wall_seconds": 3600}.items():
        positive(limits[name], maximum)
    if type(limits["max_redirects"]) is not int or not 0 <= limits["max_redirects"] <= 10:
        raise KarstError("invalid redirect limit")
    if limits["max_response_bytes"] > limits["max_total_response_bytes"]:
        raise KarstError("response limit exceeds total")
    result = ProbeConfig(data["profile"], tuple(data["entrypoints"]), tuple(origins),
                         networks["allowed_cidrs"], networks["denied_cidrs"], tuple(identities), Limits(**limits))
    for url in result.entrypoints:
        result.check_url(url)
    return result
