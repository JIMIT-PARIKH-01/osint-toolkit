"""
OSINT username checker (standard library only).

Checks whether a username exists on many sites by requesting each profile URL
and interpreting the HTTP status. Concurrent, read-only GETs.

For OSINT on accounts you're authorized to investigate (e.g. your own footprint).
"""

from __future__ import annotations

import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

# site -> profile URL template ({} = username)
SITES = {
    "GitHub": "https://github.com/{}",
    "GitLab": "https://gitlab.com/{}",
    "Reddit": "https://www.reddit.com/user/{}",
    "Instagram": "https://www.instagram.com/{}",
    "X / Twitter": "https://x.com/{}",
    "TikTok": "https://www.tiktok.com/@{}",
    "Twitch": "https://www.twitch.tv/{}",
    "Medium": "https://medium.com/@{}",
    "Pinterest": "https://www.pinterest.com/{}",
    "Hacker News": "https://news.ycombinator.com/user?id={}",
    "Keybase": "https://keybase.io/{}",
    "Replit": "https://replit.com/@{}",
    "Dev.to": "https://dev.to/{}",
    "HackerOne": "https://hackerone.com/{}",
}


@dataclass
class UsernameResult:
    username: str
    found: list = field(default_factory=list)       # (site, url)
    not_found: list = field(default_factory=list)    # site
    errors: list = field(default_factory=list)       # (site, msg)

    def as_text(self) -> str:
        lines = [f"Username '{self.username}':",
                 f"  found on {len(self.found)} site(s):"]
        for site, url in self.found:
            lines.append(f"    [+] {site:<14} {url}")
        if self.errors:
            lines.append(f"  {len(self.errors)} inconclusive:")
            for site, msg in self.errors:
                lines.append(f"    [?] {site:<14} {msg}")
        return "\n".join(lines)


def _check(site: str, template: str, username: str, timeout: float):
    url = template.format(username)
    req = urllib.request.Request(url, method="GET", headers={
        "User-Agent": "Mozilla/5.0 (osint-toolkit username check)"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)
        return site, url, ("found" if resp.status == 200 else str(resp.status))
    except urllib.error.HTTPError as exc:
        return site, url, ("not found" if exc.code == 404 else f"http {exc.code}")
    except (urllib.error.URLError, OSError) as exc:
        return site, url, f"error: {exc}"


def check(username: str, timeout: float = 8.0, workers: int = 12) -> UsernameResult:
    username = username.strip()
    result = UsernameResult(username=username)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_check, s, t, username, timeout)
                   for s, t in SITES.items()]
        for fut in futures:
            site, url, status = fut.result()
            if status == "found":
                result.found.append((site, url))
            elif status == "not found":
                result.not_found.append(site)
            else:
                result.errors.append((site, status))
    result.found.sort()
    result.errors.sort()
    return result
