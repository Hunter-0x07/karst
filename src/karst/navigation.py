"""Bounded static HTML navigation. Parsing saved evidence performs no requests."""

from html.parser import HTMLParser
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from karst.config import KarstError

VERSION = "html-get-navigation-v2"
MAX_ITEMS = 64
MAX_PAIRS = 32


def resolve(base, value):
    if len(value) > 4096 or "[REDACTED]" in value:
        return None
    try:
        url = urljoin(base, value)
        p = urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
            return None
        return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))
    except ValueError:
        return None


class Document(HTMLParser):
    def __init__(self, source):
        super().__init__(convert_charrefs=True)
        self.source, self.base = source, source
        self.base_seen = False
        self.links, self.forms = [], []
        self.form = None
        self.inert = []
        self.external_controls = False
        self.disabled_fieldset = False
        self.anchor = None
        self.truncated = False

    def add(self, collection, item):
        if len(self.links)+len(self.forms) >= MAX_ITEMS:
            self.truncated = True
            return False
        collection.append(item)
        return True

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style", "template", "noscript", "title"):
            self.inert.append(tag)
            return
        if self.inert:
            return
        if tag == "base" and "href" in a and not self.base_seen:
            self.base_seen = True
            self.base = resolve(self.source, a["href"] or "") or self.source
        elif tag in ("a", "area", "link") and a.get("href") is not None:
            if len(a["href"]) <= 4096:
                link = {"href": a["href"], "rel": (a.get("rel") or "")[:256], "tag": tag,
                        "text": (a.get("aria-label") or a.get("title") or "")[:512]}
                added = self.add(self.links, link)
                self.anchor = link if tag == "a" and added else None
            else:
                self.truncated = True
        elif tag == "form":
            if self.form:
                self.form["unsupported"].append("nested form")
            item = {"action": a.get("action"), "method": (a.get("method") or "get").lower(), "query": [], "unsupported": []}
            if (a.get("accept-charset") or "utf-8").lower() not in ("utf-8", "utf8"):
                item["unsupported"].append("unsupported form charset")
            self.form = item if self.add(self.forms, item) else None
        elif tag in ("input", "select", "textarea", "button"):
            if a.get("form"):
                # External controls need DOM form association, outside this parser.
                self.external_controls = True
            if not self.form or "disabled" in a or not a.get("name"):
                return
            kind = (a.get("type") or "text").lower()
            if tag != "input" or kind not in ("hidden", "text", "search", "number", "checkbox", "radio"):
                self.form["unsupported"].append("control requires explicit user choice: "+tag+"/"+kind)
                if tag == "textarea":
                    self.inert.append(tag)
                return
            if kind in ("checkbox", "radio") and "checked" not in a:
                return
            pair = [a["name"], a.get("value") if a.get("value") is not None else ("on" if kind in ("checkbox", "radio") else "")]
            if len(self.form["query"]) >= MAX_PAIRS or any(len(s) > 2048 for s in pair):
                self.form["unsupported"].append("control limit")
                self.truncated = True
            else:
                self.form["query"].append(pair)
                if any("[REDACTED]" in s for s in pair):
                    self.form["unsupported"].append("redacted form control")
        elif tag == "fieldset" and "disabled" in a:
            self.disabled_fieldset = True

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if self.inert:
            if tag == self.inert[-1]:
                self.inert.pop()
            return
        if tag == "form":
            self.form = None
        if tag == "a":
            self.anchor = None

    def handle_data(self, data):
        if self.anchor is not None and not self.inert:
            self.anchor["text"] = (self.anchor["text"]+data)[:512]


def inspect(body, source_url, check_url):
    if len(body) > 65536:
        raise KarstError("document_inspect_body_limit")
    doc = Document(source_url)
    doc.feed(body.decode("utf-8", errors="replace"))
    doc.close()
    def scoped(url):
        if not url:
            return False
        try:
            check_url(url)
            return True
        except KarstError:
            return False
    links = []
    for item in doc.links:
        url = resolve(doc.base, item.pop("href"))
        if url:
            links.append(dict(item, url=url, in_scope=scoped(url)))
    forms = []
    for item in doc.forms:
        if doc.external_controls or doc.disabled_fieldset:
            item["unsupported"].append("external controls or disabled fieldsets require DOM association")
        # Empty action submits the document URL, even when <base> is present.
        action = item.pop("action")
        url = resolve(doc.base, action) if action else source_url
        if url:
            p = urlsplit(url)
            url = urlunsplit((p.scheme, p.netloc, p.path, "", ""))
        allowed = item["method"] == "get" and not item["unsupported"]
        full = url+"?"+urlencode([tuple(pair) for pair in item["query"]]) if url and item["query"] else url
        forms.append(dict(item, url=url, request_url=full, in_scope=scoped(full), supported=bool(allowed and url)))
    return {"parser_version": VERSION, "source_url": source_url, "base_url": doc.base,
            "links": links, "forms": forms, "truncated": doc.truncated, "target_requests": 0,
            "limitations": "Static HTML only. No JavaScript, browser login, automatic form submission, permission or policy inference. All content is untrusted."}
