"""GitHub release checks; no GUI imports, downloads, or import-time I/O."""
from dataclasses import dataclass, replace
import math
import re
import time

import requests

from utils.config import UPDATE_CHECK_INTERVAL, claim_update_check
from utils.updater import MAX_PACKAGE_BYTES
from versions import CURRENT_VERSION

REPOSITORY = "jerry4130845-thebest/viruswise"
RELEASES_URL = f"https://github.com/{REPOSITORY}/releases"
LATEST_RELEASE_API = f"https://api.github.com/repos/{REPOSITORY}/releases/latest"
_VERSION_PATTERN = re.compile(r"([0-9]+)[.]([0-9]+)[.]([0-9]+)")


_DIGEST_PATTERN = re.compile(r"sha256:([0-9a-fA-F]{64})")


@dataclass(frozen=True)
class UpdateAsset:
    url: str
    size: int
    sha256: str


@dataclass(frozen=True)
class UpdateCheckResult:
    status: str
    message: str = ""
    latest_version: str = ""
    release_url: str = RELEASES_URL
    checked_at: float | None = None
    asset: UpdateAsset | None = None


def parse_version(version):
    """Compare integer triples, not floats or lexicographic strings."""
    if not isinstance(version, str):
        raise ValueError("Version must be a three-component string")
    match = _VERSION_PATTERN.fullmatch(version)
    if match is None:
        raise ValueError("Version must have exactly three numeric components")
    return tuple(int(part) for part in match.groups())


def seconds_until_update_check(last_checked_at, *, now=None):
    now = time.time() if now is None else now
    if (isinstance(last_checked_at, bool)
            or not isinstance(last_checked_at, (int, float))
            or not math.isfinite(last_checked_at)
            or last_checked_at <= 0 or last_checked_at > now):
        return 0
    return max(0, UPDATE_CHECK_INTERVAL - (now - last_checked_at))


def _auto_update_asset(release, tag):
    assets = release.get("assets")
    name = f"VirusWise-{tag}.zip"
    if not isinstance(assets, list):
        return None
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == name]
    if len(matches) != 1:
        return None
    asset = matches[0]
    url = f"{RELEASES_URL}/download/{tag}/{name}"
    size = asset.get("size")
    digest = asset.get("digest")
    if (asset.get("state") != "uploaded"
            or type(size) is not int or not 0 < size <= MAX_PACKAGE_BYTES
            or asset.get("browser_download_url") != url
            or not isinstance(digest, str)):
        return None
    match = _DIGEST_PATTERN.fullmatch(digest)
    return UpdateAsset(url, size, match[1].lower()) if match else None


def _fetch_latest_release():
    # Public API only: no application API keys are added to this request.
    with requests.get(
            LATEST_RELEASE_API,
            headers={"Accept": "application/vnd.github+json",
                     "User-Agent": f"VirusWise/{CURRENT_VERSION}",
                     "X-GitHub-Api-Version": "2022-11-28"},
            timeout=(5, 15)) as response:
        if response.status_code == 404:
            return UpdateCheckResult("no_release", "仓库暂时没有可用的正式 Release，或当前无法访问。")
        if response.status_code in (403, 429):
            return UpdateCheckResult("error", "GitHub 拒绝了请求或触发访问频率限制，请稍后手动重试。")
        response.raise_for_status()
        release = response.json()
    if (not isinstance(release, dict)
            or release.get("draft") is not False
            or release.get("prerelease") is not False):
        raise ValueError("GitHub 返回的不是有效的正式 Release")
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag.startswith("V"):
        return UpdateCheckResult("unsupported_tag", "当前 Release 标签不符合 Vx.y.z 格式，暂时无法判断更新。")
    try:
        latest = parse_version(tag[1:])
    except ValueError:
        return UpdateCheckResult("unsupported_tag", "当前 Release 标签不符合 Vx.y.z 格式，暂时无法判断更新。")
    version = tag[1:]
    # Build a trusted URL ourselves; do not open an arbitrary API-provided URL.
    url = f"{RELEASES_URL}/tag/{tag}"
    if latest > parse_version(CURRENT_VERSION):
        return UpdateCheckResult("available", latest_version=version, release_url=url,
                                 asset=_auto_update_asset(release, tag))
    return UpdateCheckResult("up_to_date", latest_version=version, release_url=url)


def check_for_updates(*, force=False, path=None):
    """Run in a worker. Manual checks bypass the interval, not the write lock.

    Persist attempts before HTTP, including failures. If persistence fails,
    don't issue HTTP: otherwise restart loops could hammer the GitHub API.
    The optional path supports isolated verification without user config I/O.
    """
    try:
        claimed, checked_at = claim_update_check(force=force, path=path)
    except (OSError, UnicodeError, ValueError) as exc:
        return UpdateCheckResult("error", f"无法保存更新检查时间，未发送请求：{exc}")
    if not claimed:
        return UpdateCheckResult("skipped", checked_at=checked_at)
    try:
        result = _fetch_latest_release()
    except requests.Timeout:
        result = UpdateCheckResult("error", "连接 GitHub 超时，请检查网络后手动重试。")
    except requests.RequestException as exc:
        result = UpdateCheckResult("error", f"无法连接 GitHub，请稍后手动重试：{exc}")
    except (ValueError, TypeError) as exc:
        result = UpdateCheckResult("error", f"GitHub 更新数据无效：{exc}")
    return replace(result, checked_at=checked_at)
