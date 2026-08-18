"""Private Telegram-controlled archive downloader for E-Hentai and ExHentai.

Only explicitly allow-listed Telegram users in private chats can interact with
the bot. Archives are requested from the site's own archiver and saved locally;
individual gallery images are never scraped or uploaded to Telegram.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from uuid import uuid4

import httpx
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from telegram import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    Update,
)
from telegram.constants import ChatAction, ChatType
from telegram.error import NetworkError, RetryAfter, TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

LOG = logging.getLogger(__name__)
SUPPORTED_GALLERY_HOSTS: Final = frozenset({"e-hentai.org", "exhentai.org"})
KNOWN_COOKIE_NAMES: Final = frozenset({"ipb_member_id", "ipb_pass_hash", "igneous"})
REQUIRED_COOKIE_NAMES: Final = frozenset({"ipb_member_id", "ipb_pass_hash"})
GALLERY_PATH_RE: Final = re.compile(r"^/g/(?P<gid>\d+)/(?P<token>[0-9a-fA-F]+)/?$")
SAFE_FILENAME_RE: Final = re.compile(r"[^\w.()\[\] -]+", re.UNICODE)
HOSTNAME_RE: Final = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
AUTH_FAILURE_MARKERS: Final = (
    "you are not logged in",
    "please log in",
    "invalid login",
    "log in to continue",
)
RETRYABLE_STATUS_CODES: Final = frozenset({429, 500, 502, 503, 504})
MAX_HTML_BYTES: Final = 2 * 1024 * 1024
CONFIRMATION_TTL_SECONDS: Final = 10 * 60
PROGRESS_UPDATE_SECONDS: Final = 2.0
ARCHIVE_POLL_SECONDS: Final = 5
ARCHIVE_SIGNATURES: Final = (
    (b"PK\x03\x04", ".zip"),
    (b"PK\x05\x06", ".zip"),
    (b"PK\x07\x08", ".zip"),
    (b"Rar!\x1a\x07", ".rar"),
    (b"7z\xbc\xaf\x27\x1c", ".7z"),
)
ProgressCallback = Callable[[str], Awaitable[None]]


def _positive_float_env(name: str, default: str) -> float:
    try:
        value = float(os.getenv(name, default))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be numeric") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be positive")
    return value


def _positive_int_env(name: str, default: str) -> int:
    try:
        value = int(os.getenv(name, default))
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be positive")
    return value


def _parse_allowed_hosts(raw_hosts: str) -> frozenset[str]:
    hosts = set(SUPPORTED_GALLERY_HOSTS)
    for item in raw_hosts.split(","):
        host = item.strip().lower().rstrip(".")
        if not host:
            continue
        if "://" in host or not HOSTNAME_RE.fullmatch(host):
            raise RuntimeError(
                "ARCHIVE_DOWNLOAD_HOSTS must contain comma-separated hostnames"
            )
        hosts.add(host)
    return frozenset(hosts)


@dataclass(frozen=True)
class Settings:
    token: str
    allowed_user_ids: frozenset[int]
    cookie_header: str
    download_dir: Path
    archive_type: str
    max_archive_bytes: int
    max_total_bytes: int
    min_free_bytes: int
    wait_seconds: int
    queue_size: int
    archive_download_hosts: frozenset[str]

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise RuntimeError("TELEGRAM_BOT_TOKEN is required")

        try:
            allowed = frozenset(
                int(item.strip())
                for item in os.getenv("ALLOWED_TELEGRAM_USER_IDS", "").split(",")
                if item.strip()
            )
        except ValueError as exc:
            raise RuntimeError(
                "ALLOWED_TELEGRAM_USER_IDS must contain numeric Telegram user IDs"
            ) from exc
        if not allowed or any(user_id <= 0 for user_id in allowed):
            raise RuntimeError(
                "ALLOWED_TELEGRAM_USER_IDS must contain at least one positive Telegram user ID"
            )

        archive_type = os.getenv("ARCHIVE_TYPE", "org").strip().lower()
        if archive_type not in {"org", "res"}:
            raise RuntimeError("ARCHIVE_TYPE must be org or res")

        max_archive_gib = _positive_float_env("MAX_ARCHIVE_GIB", "8")
        max_total_gib = _positive_float_env("MAX_TOTAL_DOWNLOAD_GIB", "64")
        if max_total_gib < max_archive_gib:
            raise RuntimeError(
                "MAX_TOTAL_DOWNLOAD_GIB must be at least MAX_ARCHIVE_GIB"
            )

        cookie_header = validate_cookie_header(os.getenv("EH_COOKIE", ""))

        return cls(
            token=token,
            allowed_user_ids=allowed,
            cookie_header=cookie_header,
            download_dir=Path(os.getenv("DOWNLOAD_DIR", "./downloads"))
            .expanduser()
            .resolve(),
            archive_type=archive_type,
            max_archive_bytes=int(max_archive_gib * 1024**3),
            max_total_bytes=int(max_total_gib * 1024**3),
            min_free_bytes=int(_positive_float_env("MIN_FREE_DISK_GIB", "1") * 1024**3),
            wait_seconds=int(_positive_float_env("ARCHIVE_WAIT_MINUTES", "30") * 60),
            queue_size=_positive_int_env("JOB_QUEUE_SIZE", "20"),
            archive_download_hosts=_parse_allowed_hosts(
                os.getenv("ARCHIVE_DOWNLOAD_HOSTS", "")
            ),
        )


class SecretRedactingFormatter(logging.Formatter):
    """Remove configured credentials from fully rendered log records."""

    def __init__(self, fmt: str, secrets_to_redact: tuple[str, ...]) -> None:
        super().__init__(fmt)
        self.secrets_to_redact = tuple(
            sorted(
                (secret for secret in secrets_to_redact if secret),
                key=len,
                reverse=True,
            )
        )

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        for secret in self.secrets_to_redact:
            rendered = rendered.replace(secret, "<redacted>")
        return rendered


def configure_logging(settings: Settings) -> None:
    log_format = "%(asctime)s %(levelname)s %(name)s: %(message)s"
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format=log_format)
    cookie_values = tuple(parse_cookie_header(settings.cookie_header).values())
    formatter = SecretRedactingFormatter(
        log_format,
        (settings.token, settings.cookie_header, *cookie_values),
    )
    for handler in logging.getLogger().handlers:
        handler.setFormatter(formatter)

    # httpx logs full request URLs at INFO. Telegram Bot API URLs contain the
    # bot token, so dependency request logging must never inherit root INFO.
    for logger_name in ("httpx", "httpcore", "telegram.request"):
        logging.getLogger(logger_name).setLevel(logging.WARNING)


def parse_gallery_url(raw_url: str) -> tuple[str, str, str]:
    """Return (host, gid, token), accepting only a complete canonical URL."""
    parsed = urlparse(raw_url.strip())
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("The gallery URL contains an invalid port.") from exc
    host = (parsed.hostname or "").lower().rstrip(".")
    path_match = GALLERY_PATH_RE.fullmatch(parsed.path)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or host not in SUPPORTED_GALLERY_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 80, 443}
        or path_match is None
    ):
        raise ValueError(
            "Send a full E-Hentai or ExHentai gallery URL (…/g/<id>/<token>/)."
        )
    return host, path_match.group("gid"), path_match.group("token").lower()


def extract_gallery_url(text: str) -> str | None:
    """Return the first valid gallery URL in a message."""
    for candidate in re.findall(r"https?://[^\s<>]+", text, flags=re.IGNORECASE):
        candidate = candidate.rstrip(".,;:!?)]}'\"")
        try:
            parse_gallery_url(candidate)
        except ValueError:
            continue
        return candidate
    return None


def normalize_cookie_header(header: str) -> str:
    """Normalize dotenv-style quoting that Podman env files preserve literally."""
    normalized = header.strip()
    if not normalized:
        return normalized
    starts_quoted = normalized[0] in {"'", '"'}
    ends_quoted = normalized[-1] in {"'", '"'}
    if starts_quoted or ends_quoted:
        if not (starts_quoted and normalized[-1] == normalized[0]):
            raise RuntimeError("EH_COOKIE has unmatched surrounding quotes")
        normalized = normalized[1:-1].strip()
    return normalized


def parse_cookie_header(header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in normalize_cookie_header(header).split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name in KNOWN_COOKIE_NAMES and value:
            cookies[name] = value
    return cookies


def validate_cookie_header(header: str, host: str | None = None) -> str:
    normalized = normalize_cookie_header(header)
    cookies = parse_cookie_header(normalized)
    missing = REQUIRED_COOKIE_NAMES - cookies.keys()
    if missing:
        names = ", ".join(sorted(missing))
        raise RuntimeError(f"EH_COOKIE is missing required cookie(s): {names}")
    if host == "exhentai.org" and "igneous" not in cookies:
        raise RuntimeError("EH_COOKIE must include igneous for ExHentai downloads")
    return normalized


def safe_filename(name: str, fallback: str) -> str:
    cleaned = SAFE_FILENAME_RE.sub("_", name).strip(" ._")
    return (cleaned or fallback)[:180]


def filename_from_response(response: httpx.Response, fallback: str) -> str:
    disposition = response.headers.get("content-disposition", "")
    match = re.search(
        r"filename\*?=(?:UTF-8''|\")?([^\";]+)", disposition, re.IGNORECASE
    )
    return safe_filename(match.group(1) if match else fallback, fallback)


def is_archive_response(response: httpx.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    disposition = response.headers.get("content-disposition", "").lower()
    return "attachment" in disposition or any(
        archive_type in content_type
        for archive_type in ("zip", "rar", "7z", "octet-stream")
    )


def host_is_allowed(host: str | None, allowed_hosts: frozenset[str]) -> bool:
    normalized = (host or "").lower().rstrip(".")
    return any(
        normalized == allowed or normalized.endswith(f".{allowed}")
        for allowed in allowed_hosts
    )


def validate_outbound_url(url: str, allowed_hosts: frozenset[str]) -> str:
    parsed = urlparse(url)
    try:
        port = parsed.port
    except ValueError as exc:
        raise RuntimeError("The site returned an invalid download URL.") from exc
    if (
        parsed.scheme.lower() != "https"
        or not host_is_allowed(parsed.hostname, allowed_hosts)
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
    ):
        raise RuntimeError(
            "The site returned a download URL outside the configured host allow-list."
        )
    return url


def archive_link_from_html(
    html: str, page_url: str, allowed_hosts: frozenset[str] = SUPPORTED_GALLERY_HOSTS
) -> str | None:
    """Find the next official archive link and normalize the final download URL."""
    soup = BeautifulSoup(html, "html.parser")

    # The official flow first returns a continuation page, then a download page.
    # Match the same elements as JHentai before falling back to text heuristics.
    for selector, is_download_link in (
        ("#continue > a[href]", False),
        ("#db > p > a[href]", True),
    ):
        anchor = soup.select_one(selector)
        if anchor is None:
            continue
        href = urljoin(page_url, anchor["href"])
        try:
            href = validate_outbound_url(href, allowed_hosts)
        except RuntimeError:
            continue
        if is_download_link:
            parsed = urlparse(href)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query.pop("autostart", None)
            query.setdefault("start", "1")
            href = urlunparse(parsed._replace(query=urlencode(query)))
        return href

    for anchor in soup.select("a[href]"):
        href = urljoin(page_url, anchor["href"])
        parsed = urlparse(href)
        text = anchor.get_text(" ", strip=True).lower()
        if parsed.scheme.lower() != "https" or not host_is_allowed(
            parsed.hostname, allowed_hosts
        ):
            continue
        if any(
            word in text for word in ("download", "click here", "archive")
        ) or re.search(r"\.(zip|rar|7z)(?:$|[?#])", parsed.path, re.IGNORECASE):
            return href
    return None


def archive_format(path: Path) -> str | None:
    with path.open("rb") as archive_file:
        header = archive_file.read(8)
    for signature, suffix in ARCHIVE_SIGNATURES:
        if header.startswith(signature):
            return suffix
    return None


def format_bytes(byte_count: int) -> str:
    value = float(byte_count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            precision = 0 if unit == "B" else 1
            return f"{value:.{precision}f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def format_duration(seconds: float) -> str:
    total_seconds = max(0, int(seconds))
    hours, remainder = divmod(total_seconds, 3600)
    minutes, remaining_seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {remaining_seconds:02d}s"
    if minutes:
        return f"{minutes}m {remaining_seconds:02d}s"
    return f"{remaining_seconds}s"


def archive_preparation_progress_message(
    elapsed_seconds: float, check_count: int, next_check_seconds: int
) -> str:
    return (
        "⏳ Preparing archive — stage 1/2\n"
        f"Elapsed: {format_duration(elapsed_seconds)} • status check #{check_count}\n"
        f"Next update in {next_check_seconds}s"
    )


def download_progress_message(filename: str, downloaded: int, total: int | None) -> str:
    if total is not None and total > 0:
        percentage = min(100, int(downloaded * 100 / total))
        return (
            f"⬇️ Downloading {filename} — stage 2/2\n"
            f"{percentage}% — {format_bytes(downloaded)} / {format_bytes(total)}"
        )
    return (
        f"⬇️ Downloading {filename} — stage 2/2\n"
        f"Received {format_bytes(downloaded)}"
    )


@dataclass
class ArchiveJob:
    url: str
    notice: Message
    user_id: int


@dataclass(frozen=True)
class PendingDownload:
    url: str
    user_id: int
    created_at: float


class ArchiveClient:
    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self.transport = transport

    def _client(self) -> httpx.AsyncClient:
        cookies = parse_cookie_header(self.settings.cookie_header)
        jar = httpx.Cookies()
        for name, value in cookies.items():
            if name != "igneous":
                jar.set(name, value, domain=".e-hentai.org", path="/")
            jar.set(name, value, domain=".exhentai.org", path="/")
        return httpx.AsyncClient(
            cookies=jar,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=20, read=90, write=30, pool=30),
            headers={"User-Agent": "Mozilla/5.0 (compatible; PersonalArchiveBot/1.0)"},
            transport=self.transport,
        )

    async def download(self, raw_url: str, progress: ProgressCallback) -> Path:
        host, gid, gallery_token = parse_gallery_url(raw_url)
        validate_cookie_header(self.settings.cookie_header, host)
        gallery_url = f"https://{host}/g/{gid}/{gallery_token}/"
        archiver_url = f"https://{host}/archiver.php?gid={gid}&token={gallery_token}"
        self.settings.download_dir.mkdir(parents=True, exist_ok=True)

        async with self._client() as client:
            page = await self._request(
                client, "GET", archiver_url, headers={"Referer": gallery_url}
            )
            page_html = await self._read_html(page)
            self._raise_for_site_error(page, page_html)
            response = await self._submit_archive_request(
                client, page_html, archiver_url, gallery_url
            )
            await page.aclose()
            preparation_started_at = time.monotonic()
            deadline = preparation_started_at + self.settings.wait_seconds
            check_count = 0

            while True:
                if is_archive_response(response):
                    return await self._save_response(response, gid, progress)

                response_html = await self._read_html(response)
                self._raise_for_site_error(response, response_html)
                link = archive_link_from_html(
                    response_html,
                    str(response.url),
                    self.settings.archive_download_hosts,
                )
                if link:
                    referer = str(response.url)
                    await response.aclose()
                    response = await self._request(
                        client,
                        "GET",
                        link,
                        headers={"Referer": referer},
                    )
                    continue

                now = time.monotonic()
                if now >= deadline:
                    await response.aclose()
                    raise RuntimeError(
                        "The archive was not ready before the configured wait limit."
                    )
                check_count += 1
                next_check_seconds = max(
                    1, min(ARCHIVE_POLL_SECONDS, int(deadline - now))
                )
                await progress(
                    archive_preparation_progress_message(
                        now - preparation_started_at,
                        check_count,
                        next_check_seconds,
                    )
                )
                await response.aclose()
                await asyncio.sleep(next_check_seconds)
                response = await self._submit_archive_request(
                    client, page_html, archiver_url, gallery_url
                )

    async def _request(
        self, client: httpx.AsyncClient, method: str, url: str, **kwargs
    ) -> httpx.Response:
        """Send a streamed request with safe redirects and bounded GET retries."""
        current_method = method.upper()
        current_url = validate_outbound_url(url, self.settings.archive_download_hosts)
        current_kwargs = dict(kwargs)

        for _redirect in range(6):
            response = await self._send_with_retries(
                client, current_method, current_url, current_kwargs
            )
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("location")
            if not location:
                return response
            next_url = validate_outbound_url(
                urljoin(str(response.url), location),
                self.settings.archive_download_hosts,
            )
            await response.aclose()
            if response.status_code == 303 or (
                response.status_code in {301, 302}
                and current_method not in {"GET", "HEAD"}
            ):
                current_method = "GET"
                current_kwargs = {
                    key: value
                    for key, value in current_kwargs.items()
                    if key == "headers"
                }
            current_url = next_url
        raise RuntimeError("The site returned too many redirects.")

    async def _send_with_retries(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        request_kwargs: dict,
    ) -> httpx.Response:
        attempts = 3 if method in {"GET", "HEAD"} else 1
        for attempt in range(attempts):
            try:
                request = client.build_request(method, url, **request_kwargs)
                response = await client.send(request, stream=True)
            except httpx.TransportError:
                if attempt + 1 >= attempts:
                    raise
                await asyncio.sleep(2**attempt)
                continue

            if (
                response.status_code not in RETRYABLE_STATUS_CODES
                or attempt + 1 >= attempts
            ):
                return response
            delay = self._retry_delay(response, attempt)
            await response.aclose()
            await asyncio.sleep(delay)
        raise AssertionError("retry loop exited unexpectedly")

    @staticmethod
    def _retry_delay(response: httpx.Response, attempt: int) -> float:
        retry_after = response.headers.get("retry-after", "")
        try:
            return min(max(float(retry_after), 0.0), 30.0)
        except ValueError:
            return float(2**attempt)

    @staticmethod
    async def _read_html(response: httpx.Response) -> str:
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_HTML_BYTES:
                    await response.aclose()
                    raise RuntimeError(
                        "The site returned an unexpectedly large HTML response."
                    )
            except ValueError:
                LOG.warning(
                    "Ignoring malformed Content-Length header: %r", content_length
                )

        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > MAX_HTML_BYTES:
                await response.aclose()
                raise RuntimeError(
                    "The site returned an unexpectedly large HTML response."
                )
        encoding = response.encoding or "utf-8"
        return bytes(body).decode(encoding, errors="replace")

    async def _submit_archive_request(
        self,
        client: httpx.AsyncClient,
        page_html: str,
        archiver_url: str,
        gallery_url: str,
    ) -> httpx.Response:
        soup = BeautifulSoup(page_html, "html.parser")
        form = None
        action = None
        login_form_found = False
        for candidate in soup.find_all("form"):
            candidate_action = urljoin(
                archiver_url, candidate.get("action") or archiver_url
            )
            parsed_action = urlparse(candidate_action)
            input_names = {
                str(input_tag.get("name", "")).lower()
                for input_tag in candidate.select("input[name]")
            }
            if (
                "act=login" in parsed_action.query.lower()
                or any("password" in name for name in input_names)
            ):
                login_form_found = True
                continue
            if parsed_action.path.lower().endswith("/archiver.php"):
                form = candidate
                action = candidate_action
                break
        if not form:
            if login_form_found:
                raise RuntimeError(
                    "The configured session is not logged in or has expired. Refresh EH_COOKIE."
                )
            raise RuntimeError(
                "Could not find the archive form. Check that the account is eligible for archive downloads."
            )
        data = {
            "dltype": self.settings.archive_type,
            "dlcheck": (
                "Download Original Archive"
                if self.settings.archive_type == "org"
                else "Download Resample Archive"
            ),
        }
        action = validate_outbound_url(action, SUPPORTED_GALLERY_HOSTS)
        return await self._request(
            client,
            "POST",
            action,
            files={name: (None, value) for name, value in data.items()},
            headers={"Referer": gallery_url},
        )

    @staticmethod
    def _raise_for_site_error(response: httpx.Response, response_html: str) -> None:
        parsed_url = urlparse(str(response.url))
        if response.status_code in {401, 403} and (
            "act=login" in parsed_url.query.lower()
            or (
                (parsed_url.hostname or "").lower() == "forums.e-hentai.org"
                and parsed_url.path.lower().endswith("/index.php")
            )
        ):
            raise RuntimeError(
                "The configured session is not logged in or has expired. Refresh EH_COOKIE."
            )
        response.raise_for_status()
        text = response_html.lower()
        if any(marker in text for marker in AUTH_FAILURE_MARKERS):
            raise RuntimeError(
                "The configured session is not logged in or has expired. Refresh EH_COOKIE."
            )
        if "sad panda" in text or (
            "exhentai.org" in str(response.url) and "restricted" in text
        ):
            raise RuntimeError(
                "This account cannot access ExHentai from the current network/session."
            )
        if "insufficient funds" in text or "insufficient gp" in text:
            raise RuntimeError(
                "The account does not have enough archive points for this download."
            )

    def _storage_budget(self) -> int:
        existing_bytes = sum(
            entry.stat().st_size
            for entry in self.settings.download_dir.iterdir()
            if entry.is_file() and not entry.name.endswith(".part")
        )
        quota_remaining = self.settings.max_total_bytes - existing_bytes
        disk_remaining = (
            shutil.disk_usage(self.settings.download_dir).free
            - self.settings.min_free_bytes
        )
        budget = min(self.settings.max_archive_bytes, quota_remaining, disk_remaining)
        if budget <= 0:
            raise RuntimeError(
                "Download storage quota or minimum free-disk reserve has been reached."
            )
        return budget

    def _unique_destination(self, filename: str, gid: str) -> Path:
        destination = self.settings.download_dir / filename
        if not destination.exists():
            return destination
        return (
            self.settings.download_dir
            / f"{destination.stem}-{gid}-{uuid4().hex[:8]}{destination.suffix}"
        )

    def _commit_temporary(self, temporary: Path, filename: str, gid: str) -> Path:
        """Publish a complete file atomically without overwriting any path."""
        while True:
            destination = self._unique_destination(filename, gid)
            try:
                os.link(temporary, destination)
            except FileExistsError:
                continue
            temporary.unlink()
            return destination

    async def _save_response(
        self, response: httpx.Response, gid: str, progress: ProgressCallback
    ) -> Path:
        temporary: Path | None = None
        try:
            budget = self._storage_budget()
            length_header = response.headers.get("content-length")
            total_bytes: int | None = None
            if length_header:
                try:
                    parsed_length = int(length_header)
                    if parsed_length > budget:
                        raise RuntimeError(
                            "The archive exceeds the configured storage limits and was not saved."
                        )
                    if parsed_length > 0:
                        total_bytes = parsed_length
                except ValueError:
                    LOG.warning(
                        "Ignoring malformed Content-Length header: %r", length_header
                    )

            filename = filename_from_response(response, f"ehentai-{gid}.zip")
            temporary = self.settings.download_dir / f".{uuid4().hex}.part"
            written = 0
            last_reported_bytes = 0
            last_reported_percentage = 0
            last_progress_at = time.monotonic()
            await progress(download_progress_message(filename, 0, total_bytes))
            with temporary.open("xb") as file_handle:
                async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                    written += len(chunk)
                    if written > budget:
                        raise RuntimeError(
                            "The archive exceeded the configured storage limits; the partial file was removed."
                        )
                    file_handle.write(chunk)
                    current_percentage = (
                        min(100, int(written * 100 / total_bytes))
                        if total_bytes is not None
                        else None
                    )
                    now = time.monotonic()
                    percentage_advanced = (
                        current_percentage is not None
                        and current_percentage >= last_reported_percentage + 5
                    )
                    if (
                        percentage_advanced
                        or now - last_progress_at >= PROGRESS_UPDATE_SECONDS
                    ):
                        await progress(
                            download_progress_message(filename, written, total_bytes)
                        )
                        last_reported_bytes = written
                        last_reported_percentage = current_percentage or 0
                        last_progress_at = now
                file_handle.flush()
                os.fsync(file_handle.fileno())

            if written != last_reported_bytes:
                await progress(
                    download_progress_message(filename, written, total_bytes)
                )
            await progress(
                f"🔎 Download received: {filename}\n"
                f"{format_bytes(written)} — validating archive…"
            )

            detected_suffix = archive_format(temporary)
            if detected_suffix is None:
                raise RuntimeError(
                    "The downloaded response was not a recognized ZIP, RAR, or 7z archive."
                )
            declared_suffix = Path(filename).suffix.lower()
            if declared_suffix in {".zip", ".rar", ".7z"}:
                if declared_suffix != detected_suffix:
                    filename = f"{Path(filename).stem}{detected_suffix}"
            else:
                filename = f"{filename}{detected_suffix}"
            return self._commit_temporary(temporary, filename, gid)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            await response.aclose()


class BotService:
    def __init__(self, settings: Settings, client: ArchiveClient | None = None) -> None:
        self.settings = settings
        self.client = client or ArchiveClient(settings)
        self.queue: asyncio.Queue[ArchiveJob] = asyncio.Queue(
            maxsize=settings.queue_size
        )
        self.active_job: ArchiveJob | None = None
        self.worker_task: asyncio.Task[None] | None = None
        self.pending_downloads: dict[str, PendingDownload] = {}

    def authorized(self, update: Update) -> bool:
        user = update.effective_user
        chat = update.effective_chat
        return (
            user is not None
            and user.id in self.settings.allowed_user_ids
            and chat is not None
            and chat.type == ChatType.PRIVATE
        )

    async def post_init(self, application: Application) -> None:
        self.worker_task = asyncio.create_task(self._worker(), name="archive-worker")

    async def post_shutdown(self, application: Application) -> None:
        if self.worker_task is None:
            return
        self.worker_task.cancel()
        with suppress(asyncio.CancelledError):
            await self.worker_task

    async def _safe_edit(self, notice: Message, message: str) -> None:
        for attempt in range(3):
            try:
                await notice.edit_text(message, reply_markup=None)
                return
            except RetryAfter as exc:
                retry_after = exc.retry_after
                delay = (
                    retry_after.total_seconds()
                    if hasattr(retry_after, "total_seconds")
                    else float(retry_after)
                )
                await asyncio.sleep(min(max(delay, 0.0), 30.0))
            except NetworkError:
                if attempt == 2:
                    LOG.exception("Could not update Telegram job notice")
                    return
                await asyncio.sleep(2**attempt)
            except TelegramError:
                LOG.exception("Could not update Telegram job notice")
                return
        LOG.warning("Could not update Telegram job notice after retries")

    @staticmethod
    async def _safe_answer(
        query: CallbackQuery, message: str | None = None, *, show_alert: bool = False
    ) -> None:
        try:
            await query.answer(message, show_alert=show_alert)
        except TelegramError:
            LOG.warning("Could not answer Telegram callback query", exc_info=True)

    def _prune_pending_downloads(self) -> None:
        cutoff = time.monotonic() - CONFIRMATION_TTL_SECONDS
        expired = [
            request_id
            for request_id, pending in self.pending_downloads.items()
            if pending.created_at < cutoff
        ]
        for request_id in expired:
            self.pending_downloads.pop(request_id, None)

    async def _worker(self) -> None:
        while True:
            job = await self.queue.get()
            self.active_job = job

            async def progress(message: str, notice: Message = job.notice) -> None:
                await self._safe_edit(notice, message)

            try:
                archive = await self.client.download(job.url, progress)
                await self._safe_edit(
                    job.notice,
                    f"✅ Download completed successfully\n"
                    f"File: {archive.name}\n"
                    f"Size: {format_bytes(archive.stat().st_size)}\n"
                    f"Saved to: {archive.parent}",
                )
            except asyncio.CancelledError:
                await self._safe_edit(
                    job.notice, "Download interrupted because the bot is stopping."
                )
                raise
            except (httpx.HTTPError, RuntimeError, ValueError) as exc:
                LOG.warning("Download failed for user %s: %s", job.user_id, exc)
                await self._safe_edit(job.notice, f"❌ Download failed\n{exc}")
            except Exception:
                LOG.exception("Unexpected download failure for user %s", job.user_id)
                await self._safe_edit(
                    job.notice,
                    "❌ Download failed unexpectedly\nCheck the bot logs for details.",
                )
            finally:
                self.active_job = None
                self.queue.task_done()

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.authorized(update):
            return
        await update.effective_message.reply_text(
            "Send or forward an E-Hentai or ExHentai gallery URL.\n"
            "I’ll ask for confirmation before queueing it.\n"
            "Use /status to check configuration and queue state."
        )

    async def whoami(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.authorized(update):
            return
        await update.effective_message.reply_text(
            f"Your Telegram user ID: {update.effective_user.id}"
        )

    async def status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.authorized(update):
            return
        cookie_state = "configured" if self.settings.cookie_header else "missing"
        active_state = "active" if self.active_job else "idle"
        await update.effective_message.reply_text(
            f"Site session: {cookie_state}\n"
            f"Destination: {self.settings.download_dir}\n"
            f"Format: {self.settings.archive_type}\n"
            f"Worker: {active_state}\n"
            f"Queued: {self.queue.qsize()}"
        )

    async def gallery_message(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not self.authorized(update):
            return
        message = update.effective_message
        text = message.text or message.caption or ""
        gallery_url = extract_gallery_url(text)
        if gallery_url is None:
            await message.reply_text(
                "I couldn’t find a valid E-Hentai or ExHentai gallery URL in that message."
            )
            return

        await message.reply_chat_action(ChatAction.TYPING)
        self._prune_pending_downloads()
        if len(self.pending_downloads) >= self.settings.queue_size:
            await message.reply_text(
                "There are too many requests awaiting confirmation. Respond to an existing prompt first."
            )
            return

        request_id = uuid4().hex
        archive_label = (
            "original files"
            if self.settings.archive_type == "org"
            else "resampled files"
        )
        keyboard = InlineKeyboardMarkup(
            [
                [
                    InlineKeyboardButton(
                        "✅ Yes, download",
                        callback_data=f"archive:confirm:{request_id}",
                    ),
                    InlineKeyboardButton(
                        "❌ No, cancel", callback_data=f"archive:cancel:{request_id}"
                    ),
                ]
            ]
        )
        await message.reply_text(
            f"Download this gallery?\n\n{gallery_url}\n\nArchive: {archive_label}",
            reply_markup=keyboard,
        )
        self.pending_downloads[request_id] = PendingDownload(
            url=gallery_url,
            user_id=update.effective_user.id,
            created_at=time.monotonic(),
        )

    async def confirm_download(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        if not self.authorized(update) or update.callback_query is None:
            return
        query = update.callback_query
        data = query.data or ""
        try:
            _prefix, action, request_id = data.split(":", 2)
        except ValueError:
            await self._safe_answer(query, "Invalid download request.", show_alert=True)
            return
        if action not in {"confirm", "cancel"}:
            await self._safe_answer(query, "Invalid download request.", show_alert=True)
            return

        self._prune_pending_downloads()
        pending = self.pending_downloads.get(request_id)
        if pending is None:
            await self._safe_answer(
                query, "This confirmation has expired.", show_alert=True
            )
            if query.message is not None:
                await self._safe_edit(
                    query.message, "This download confirmation has expired."
                )
            return
        if pending.user_id != update.effective_user.id:
            await self._safe_answer(
                query, "This confirmation belongs to another user.", show_alert=True
            )
            return

        self.pending_downloads.pop(request_id, None)
        await self._safe_answer(query)
        if query.message is None:
            return
        if action == "cancel":
            await self._safe_edit(query.message, "Download cancelled.")
            return

        queue_position = self.queue.qsize() + (1 if self.active_job else 0) + 1
        try:
            self.queue.put_nowait(
                ArchiveJob(
                    url=pending.url,
                    notice=query.message,
                    user_id=update.effective_user.id,
                )
            )
        except asyncio.QueueFull:
            await self._safe_edit(
                query.message, "The download queue is full; try again later."
            )
            return
        await self._safe_edit(
            query.message, f"⏳ Confirmed and queued at position {queue_position}."
        )


def main() -> None:
    settings = Settings.from_env()
    configure_logging(settings)
    service = BotService(settings)
    app = (
        Application.builder()
        .token(settings.token)
        .concurrent_updates(8)
        .post_init(service.post_init)
        .post_shutdown(service.post_shutdown)
        .build()
    )
    app.add_handler(CommandHandler("start", service.start))
    app.add_handler(CommandHandler("whoami", service.whoami))
    app.add_handler(CommandHandler("status", service.status))
    app.add_handler(
        CallbackQueryHandler(
            service.confirm_download,
            pattern=r"^archive:(?:confirm|cancel):[0-9a-f]{32}$",
        )
    )
    app.add_handler(
        MessageHandler(
            (filters.TEXT | filters.CAPTION) & ~filters.COMMAND, service.gallery_message
        )
    )
    LOG.info("Bot starting; destination is %s", settings.download_dir)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
