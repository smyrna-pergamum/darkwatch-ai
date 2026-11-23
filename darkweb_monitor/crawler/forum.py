"""Forum post extraction for darknet forum monitoring.

Recognises the common engines (phpBB, XenForo, MyBB, vBulletin, SMF, Discourse
style markup) and a generic fallback (elements whose class mentions "post"
with an author element inside). Returns author handle, timestamp text, the
post body and contact handles found in the post, so authors can be profiled
as threat actors."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from bs4 import BeautifulSoup, Tag

# (container selector, author selector, body selector, time selector)
_ENGINES: list[tuple[str, str, str, str]] = [
    ("div.post", ".author strong, .author a.username, .username, .postauthor", ".content, .postbody", ".author time, time, .postdate"),           # phpBB
    ("article.message", ".message-name .username, .username", ".message-body .bbWrapper, .message-body", "time"),                               # XenForo
    ("div.post_block, div.post", ".post_author a, .largetext a", ".post_body", ".post_date"),                                                     # MyBB
    ("li.postcontainer, div.postbit", ".username, .postbit_username", ".postcontent, blockquote.postcontent", ".date, .postdate"),               # vBulletin
    ("div.windowbg, div.post_wrapper", ".poster h4 a, .poster a", ".post .inner, .inner", ".smalltext, .keyinfo .smalltext"),                    # SMF
    ("div.topic-post, article.boxed", ".names .username, .username", ".cooked", ".post-date, time"),                                            # Discourse
]
_GENERIC_CONTAINER = re.compile(r"\b(post|message|comment|reply|entry)\b", re.IGNORECASE)
_GENERIC_AUTHOR = re.compile(r"(author|username|user-name|poster|nick)", re.IGNORECASE)

CONTACT_PATTERNS: dict[str, re.Pattern] = {
    "telegram": re.compile(r"(?:t\.me/|telegram\s*(?:id)?\s*[:=]\s*@?|telegram\s+@|\btg\s*[:=]\s*@?)([A-Za-z][A-Za-z0-9_]{4,31})",
                          re.IGNORECASE),
    "jabber": re.compile(r"(?:jabber|xmpp|jid)\s*[:=]?\s*([A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE),
    "tox": re.compile(r"\btox(?:\s*id)?\s*[:=]?\s*([A-F0-9]{76})\b", re.IGNORECASE),
    "session": re.compile(r"\bsession(?:\s*id)?\s*[:=]\s*(05[a-f0-9]{64})\b", re.IGNORECASE),
}
_BAD_HANDLES = {"guest", "anonymous", "admin", "administrator", "moderator", "deleted", "unknown", "system"}


@dataclass
class ForumPost:
    author: str
    body: str
    posted: str = ""
    contacts: list[tuple[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"author": self.author, "posted": self.posted, "body": self.body[:2000],
                "contacts": [{"platform": p, "value": v} for p, v in self.contacts]}


def _text(el: Tag | None) -> str:
    return " ".join(el.get_text(" ", strip=True).split()) if el else ""


def clean_handle(raw: str) -> str:
    h = re.sub(r"\s+", " ", (raw or "").strip()).strip("@:")
    if not (2 <= len(h) <= 64) or h.lower() in _BAD_HANDLES:
        return ""
    return h


def contacts_in(text: str) -> list[tuple[str, str]]:
    out, seen = [], set()
    for platform, pat in CONTACT_PATTERNS.items():
        for m in pat.finditer(text or ""):
            v = m.group(1)
            v = v.lower() if platform in ("telegram", "jabber") else v
            if (platform, v) not in seen:
                seen.add((platform, v))
                out.append((platform, v))
    return out[:20]


def _from_engine(soup: BeautifulSoup) -> list[ForumPost]:
    for container, author_sel, body_sel, time_sel in _ENGINES:
        posts = []
        for el in soup.select(container)[:200]:
            author = clean_handle(_text(el.select_one(author_sel)))
            body_el = el.select_one(body_sel)
            body = _text(body_el)
            if not author or not body:
                continue
            t = el.select_one(time_sel)
            posted = (t.get("datetime") or _text(t)) if t else ""
            posts.append(ForumPost(author=author, body=body, posted=str(posted)[:64]))
        if posts:
            return posts
    return []


def _generic(soup: BeautifulSoup) -> list[ForumPost]:
    posts = []
    for el in soup.find_all(["div", "article", "li", "section"], class_=_GENERIC_CONTAINER)[:200]:
        a = el.find(class_=_GENERIC_AUTHOR)
        if not a:
            continue
        author = clean_handle(_text(a))
        body = _text(el)
        if author and author in body:
            body = body.replace(author, "", 1).strip()
        if author and len(body) >= 10:
            posts.append(ForumPost(author=author, body=body))
    # nested containers produce duplicates - keep the innermost (shortest) per author+prefix
    uniq: dict[tuple[str, str], ForumPost] = {}
    for p in sorted(posts, key=lambda p: len(p.body)):
        uniq.setdefault((p.author, p.body[:40]), p)
    return list(uniq.values())


def parse_forum(html: str, limit: int = 100) -> list[ForumPost]:
    if not html or len(html) < 50:
        return []
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript", "template"]):
        tag.decompose()
    posts = _from_engine(soup) or _generic(soup)
    for p in posts:
        p.contacts = contacts_in(p.body)
    return posts[:limit]
