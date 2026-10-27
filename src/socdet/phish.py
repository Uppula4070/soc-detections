"""Triage a reported email (.eml): authentication results, sender spoofing, lookalike domains, links and attachments.

Everything runs offline on the message itself. The output is a scored verdict plus a ticket summary an
analyst can paste into the case, with every reason listed so the score can be checked by a person.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit

RISKY_EXTENSIONS = {
    ".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".hta", ".lnk", ".iso", ".img", ".vhd",
    ".one", ".html", ".htm", ".svg", ".docm", ".xlsm", ".pptm", ".bat", ".cmd", ".ps1", ".msi", ".zip",
}  # fmt: skip
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "rb.gy", "cutt.ly"}
PRESSURE_WORDS = [
    "urgent", "immediately", "suspended", "unusual activity", "password expires",
    "wire transfer", "gift card", "within 24 hours", "final notice",
]  # fmt: skip
# Asking the reader to sign in through a link is how credential-harvesting pages are reached.
CREDENTIAL_LURES = [
    "verify your account", "verify your identity", "confirm your account", "sign in to view",
    "log in to view", "update your password", "re-enter your password", "validate your mailbox",
]  # fmt: skip
URL_PATTERN = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)
# Points per finding; >= 60 malicious, >= 30 suspicious.
WEIGHTS = {
    "spf_fail": 15, "dkim_fail": 15, "dmarc_fail": 25, "reply_to_mismatch": 15, "return_path_mismatch": 10,
    "display_name_spoof": 25, "lookalike_sender": 35, "lookalike_link": 30, "punycode": 20, "link_text_mismatch": 20,
    "ip_link": 15, "shortener": 10, "risky_attachment": 30, "double_extension": 20, "pressure_language": 10,
    "credential_lure": 20,
}  # fmt: skip
MALICIOUS, SUSPICIOUS = 60, 30


@dataclass
class Finding:
    key: str
    detail: str

    @property
    def points(self) -> int:
        return WEIGHTS[self.key]


@dataclass
class Report:
    subject: str
    sender: str
    sender_domain: str
    auth: dict[str, str]
    urls: list[str]
    attachments: list[str]
    findings: list[Finding] = field(default_factory=list)

    @property
    def score(self) -> int:
        # Count each kind of finding once, so ten bad links don't outweigh a failed DMARC check.
        return min(100, sum(WEIGHTS[k] for k in {f.key for f in self.findings}))

    @property
    def verdict(self) -> str:
        if self.score >= MALICIOUS:
            return "malicious"
        return "suspicious" if self.score >= SUSPICIOUS else "likely benign"


class _Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[tuple[str, str]] = []  # (href, visible text)
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._text).strip()))
            self._href = None


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].strip().strip(">").lower() if "@" in address else ""


def registrable(domain: str) -> str:
    """Last two labels: good enough to compare example.com with mail.example.com without a suffix list."""
    parts = domain.lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain.lower()


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(domain: str, protected: list[str]) -> str | None:
    """Return the protected domain this one imitates, or None. Exact matches and subdomains are not lookalikes."""
    domain = domain.lower()
    reg = registrable(domain)
    for p in protected:
        p = p.lower()
        if reg == p:
            return None
    for p in protected:
        p = p.lower()
        if 0 < edit_distance(reg, p) <= 2:
            return p
        if p.split(".")[0] in domain.split(".")[:-2] or domain.startswith(p + "."):
            return p  # e.g. samplelending.example.login-check.net
    return None


def _auth_results(msg: EmailMessage) -> dict[str, str]:
    header = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    out = {}
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", header, re.IGNORECASE)
        out[mech] = m.group(1).lower() if m else "none"
    return out


def _bodies(msg: EmailMessage) -> tuple[str, str]:
    text, html = [], []
    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):
            continue
        if part.get_content_type() == "text/plain":
            text.append(content)
        elif part.get_content_type() == "text/html":
            html.append(content)
    return "\n".join(text), "\n".join(html)


def analyze(raw: bytes, protected: list[str]) -> Report:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    display, address = parseaddr(str(msg.get("From", "")))
    sender_domain = domain_of(address)
    text, html = _bodies(msg)
    parser = _Links()
    parser.feed(html)
    urls = sorted(set(URL_PATTERN.findall(text)) | {h for h, _ in parser.links if h.lower().startswith("http")})
    attachments = [p.get_filename() or "(unnamed)" for p in msg.iter_attachments()]
    report = Report(str(msg.get("Subject", "")), address, sender_domain, _auth_results(msg), urls, attachments)
    add = report.findings.append

    for mech in ("spf", "dkim", "dmarc"):
        if report.auth[mech] in ("fail", "softfail"):
            add(Finding(f"{mech}_fail", f"{mech.upper()} result is {report.auth[mech]}"))
    reply_domain = domain_of(parseaddr(str(msg.get("Reply-To", "")))[1])
    if reply_domain and registrable(reply_domain) != registrable(sender_domain):
        add(Finding("reply_to_mismatch", f"replies go to {reply_domain}, not the sender's domain {sender_domain}"))
    rp_domain = domain_of(str(msg.get("Return-Path", "")))
    if rp_domain and registrable(rp_domain) != registrable(sender_domain):
        add(Finding("return_path_mismatch", f"bounce address domain {rp_domain} differs from {sender_domain}"))

    imitated = lookalike_of(sender_domain, protected)
    if imitated:
        add(Finding("lookalike_sender", f"sender domain {sender_domain} imitates {imitated}"))
    if any(registrable(sender_domain) != p and p.split(".")[0] in display.lower() for p in protected):
        add(
            Finding(
                "display_name_spoof", f"display name '{display}' uses a trusted name but is sent from {sender_domain}"
            )
        )

    for url in urls:
        host = (urlsplit(url).hostname or "").lower()
        if not host:
            continue
        if host.startswith("xn--") or ".xn--" in host:
            add(Finding("punycode", f"internationalized (punycode) domain in link: {host}"))
        try:
            ipaddress.ip_address(host)
            add(Finding("ip_link", f"link points to a bare IP address: {url}"))
        except ValueError:
            pass
        if registrable(host) in SHORTENERS:
            add(Finding("shortener", f"link uses a URL shortener: {host}"))
        target = lookalike_of(host, protected)
        if target:
            add(Finding("lookalike_link", f"link domain {host} imitates {target}"))
    for href, label in parser.links:
        shown = URL_PATTERN.search(label) or re.search(r"\b[\w-]+(\.[\w-]+)+\b", label)
        href_host = (urlsplit(href).hostname or "").lower()
        if shown and href_host:
            shown_host = (urlsplit(shown.group(0)).hostname or shown.group(0)).lower()
            if "." in shown_host and registrable(shown_host) != registrable(href_host):
                add(Finding("link_text_mismatch", f"link text shows {shown_host} but goes to {href_host}"))

    for name in attachments:
        lower = name.lower()
        suffixes = Path(lower).suffixes
        if suffixes and suffixes[-1] in RISKY_EXTENSIONS:
            add(Finding("risky_attachment", f"attachment type often used for malware: {name}"))
        if len(suffixes) >= 2 and suffixes[-2] in {".pdf", ".doc", ".docx", ".xlsx", ".jpg", ".png", ".txt"}:
            add(Finding("double_extension", f"double extension hides the real file type: {name}"))

    body = f"{report.subject}\n{text}\n{html}".lower()
    hits = [w for w in PRESSURE_WORDS if w in body]
    if hits:
        add(Finding("pressure_language", "urgency or pressure wording: " + ", ".join(hits[:4])))
    lures = [w for w in CREDENTIAL_LURES if w in body]
    if lures and urls:
        add(Finding("credential_lure", f"asks the reader to '{lures[0]}' through a link"))
    return report


def analyze_file(path: str | Path, protected: list[str]) -> Report:
    return analyze(Path(path).read_bytes(), protected)


def ticket(report: Report, name: str = "") -> str:
    lines = [f"## Phishing triage: {report.verdict.upper()} (score {report.score}/100)", ""]
    if name:
        lines.append(f"- **File:** {name}")
    lines += [
        f"- **Subject:** {report.subject}",
        f"- **From:** {report.sender}",
        f"- **Authentication:** SPF {report.auth['spf']}, DKIM {report.auth['dkim']}, DMARC {report.auth['dmarc']}",
        f"- **Links:** {len(report.urls)} · **Attachments:** {', '.join(report.attachments) or 'none'}",
        "",
        "**Why:**",
    ]
    lines += [f"- (+{f.points}) {f.detail}" for f in report.findings] or ["- No warning signs found."]
    lines += ["", "**Recommended actions:**"]
    if report.verdict == "malicious":
        lines += [
            "- Purge the message from all mailboxes and block the sender domain and link domains.",
            "- Check mail and proxy logs for anyone who clicked or replied; reset credentials for anyone who did.",
        ]
    elif report.verdict == "suspicious":
        lines += [
            "- Hold the message for analyst review before releasing it.",
            "- Ask the reporter whether they clicked.",
        ]
    else:
        lines += ["- Thank the reporter and close; no action needed."]
    return "\n".join(lines) + "\n"
