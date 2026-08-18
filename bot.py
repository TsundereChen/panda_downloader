"""Private Telegram-controlled archive downloader for E-Hentai and ExHentai.

Only explicitly allow-listed Telegram users in private chats can interact with
the bot. Archives are requested from the site's own archiver and saved locally;
individual gallery images are never scraped or uploaded to Telegram.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import re
import shutil
import sys
import threading
import time
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from uuid import uuid4

import httpx
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from telegram import (
    CallbackQuery,
    InputFile,
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
APP_SOURCE_FILE: Final = str(Path(__file__).resolve())
SUPPORTED_GALLERY_HOSTS: Final = frozenset({"e-hentai.org", "exhentai.org"})
DEFAULT_ARCHIVE_DOWNLOAD_HOSTS: Final = frozenset(
    {*SUPPORTED_GALLERY_HOSTS, "hath.network"}
)
DEFAULT_GALLERY_IMAGE_HOSTS: Final = frozenset(
    {*SUPPORTED_GALLERY_HOSTS, "ehgt.org"}
)
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
MAX_GALLERY_PREVIEW_BYTES: Final = 10 * 1024 * 1024
MAX_TELEGRAM_CAPTION_CHARS: Final = 1024
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


def _function_trace_profile(frame, event: str, arg) -> None:
    """Log calls and returns for functions defined in this application module."""
    if event not in {"call", "return"} or frame.f_code.co_filename != APP_SOURCE_FILE:
        return
    function_name = frame.f_code.co_qualname
    if function_name in {
        "_function_trace_profile",
        "SecretRedactingFormatter.format",
    }:
        return
    LOG.info("function event=%s name=%s", event, function_name)


def enable_function_call_logging() -> None:
    """Enable argument-free function tracing unless explicitly disabled."""
    enabled = os.getenv("FUNCTION_TRACE_LOGGING", "true").strip().lower()
    if enabled in {"0", "false", "no", "off"}:
        LOG.info("function tracing disabled by FUNCTION_TRACE_LOGGING")
        return
    sys.setprofile(_function_trace_profile)
    threading.setprofile(_function_trace_profile)
    LOG.info(
        "function tracing enabled for application functions; arguments and return values are omitted"
    )


def safe_url_for_log(url: str) -> str:
    """Return a URL location without credentials, query parameters, or fragments."""
    parsed = urlparse(url)
    host = (parsed.hostname or "unknown").lower().rstrip(".")
    return f"{parsed.scheme.lower() or 'unknown'}://{host}{safe_path_for_log(parsed.path)}"


def safe_path_for_log(path: str) -> str:
    """Keep a route name while hiding deeper path segments that may be tokens."""
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return "/"
    if len(segments) == 1:
        return f"/{segments[0]}"
    return f"/{segments[0]}/<redacted>"


def archive_html_state(html: str) -> str:
    """Describe archive HTML structurally without logging page content."""
    soup = BeautifulSoup(html, "html.parser")
    input_names = {
        str(input_tag.get("name", "")).lower()
        for input_tag in soup.select("input[name]")
    }
    login_form = any(
        "password" in {
            str(input_tag.get("name", "")).lower()
            for input_tag in form.select("input[name]")
        }
        for form in soup.find_all("form")
    )
    normalized = soup.get_text(" ", strip=True).lower()
    waiting_marker = any(
        marker in normalized
        for marker in ("being generated", "preparing", "please wait", "not ready")
    )
    body_hash = hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest()[:16]
    return (
        f"html_bytes={len(html.encode('utf-8', errors='replace'))} "
        f"body_sha256={body_hash} forms={len(soup.find_all('form'))} "
        f"dltype_field={'dltype' in input_names} "
        f"dlcheck_field={'dlcheck' in input_names} "
        f"continue_link={bool(soup.select_one('#continue > a[href]'))} "
        f"download_link={bool(soup.select_one('#db > p > a[href]'))} "
        f"login_form={login_form} waiting_marker={waiting_marker}"
    )


def log_response_step(
    step: str,
    response: httpx.Response,
    *,
    html: str | None = None,
    check_count: int | None = None,
) -> None:
    """Log a sanitized HTTP/archive state transition."""
    content_type = response.headers.get("content-type", "unknown").split(";", 1)[0]
    LOG.info(
        "archive step=%s method=%s location=%s status=%s content_type=%s "
        "content_length=%s check=%s archive_response=%s%s",
        step,
        response.request.method,
        safe_url_for_log(str(response.url)),
        response.status_code,
        content_type,
        response.headers.get("content-length", "unknown"),
        check_count if check_count is not None else "none",
        is_archive_response(response),
        f" {archive_html_state(html)}" if html is not None else "",
    )


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
    hosts = set(DEFAULT_ARCHIVE_DOWNLOAD_HOSTS)
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
        rendered = re.sub(
            r"(https?://[^\s?'\"<>]+)\?[^\s'\"<>]+",
            r"\1?<redacted-query>",
            rendered,
            flags=re.IGNORECASE,
        )
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
    LOG.info(
        "logging configured level=%s dependency_request_logging=warning",
        os.getenv("LOG_LEVEL", "INFO").upper(),
    )


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
    html: str,
    page_url: str,
    allowed_hosts: frozenset[str] = DEFAULT_ARCHIVE_DOWNLOAD_HOSTS,
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
            LOG.info("archive step=link_selector_empty selector=%s", selector)
            continue
        href = urljoin(page_url, anchor["href"])
        LOG.info(
            "archive step=link_candidate selector=%s location=%s",
            selector,
            safe_url_for_log(href),
        )
        try:
            href = validate_outbound_url(href, allowed_hosts)
        except RuntimeError as exc:
            parsed = urlparse(href)
            LOG.warning(
                "archive step=link_candidate_rejected selector=%s scheme=%s host=%s "
                "path=%s reason=%s",
                selector,
                parsed.scheme.lower() or "none",
                (parsed.hostname or "none").lower().rstrip("."),
                safe_path_for_log(parsed.path),
                exc,
            )
            continue
        if is_download_link:
            parsed = urlparse(href)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query.pop("autostart", None)
            query.setdefault("start", "1")
            href = urlunparse(parsed._replace(query=urlencode(query)))
        LOG.info(
            "archive step=link_candidate_accepted selector=%s location=%s",
            selector,
            safe_url_for_log(href),
        )
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


@dataclass(frozen=True)
class GalleryPreview:
    gallery_name: str
    english_name: str
    language: str
    file_size: str
    length: str
    image_url: str | None
    image: bytes | None = None


def gallery_preview_from_html(html: str, page_url: str) -> GalleryPreview:
    """Parse the decision-making metadata shown on an official gallery page."""
    soup = BeautifulSoup(html, "html.parser")
    english_name = soup.select_one("#gn")
    gallery_name = soup.select_one("#gj")
    english_text = english_name.get_text(" ", strip=True) if english_name else ""
    gallery_text = gallery_name.get_text(" ", strip=True) if gallery_name else ""

    details: dict[str, str] = {}
    for row in soup.select("#gdd tr"):
        label = row.select_one(".gdt1")
        value = row.select_one(".gdt2")
        if label is None or value is None:
            continue
        key = label.get_text(" ", strip=True).rstrip(":").lower()
        if key == "language":
            direct_text = value.find(string=True, recursive=False)
            details[key] = (
                str(direct_text).strip()
                if direct_text and str(direct_text).strip()
                else value.get_text(" ", strip=True)
            )
        else:
            details[key] = value.get_text(" ", strip=True)

    image_url: str | None = None
    image = soup.select_one("#gd1 img[src]")
    if image is not None:
        image_url = urljoin(page_url, str(image["src"]))
    else:
        cover = soup.select_one("#gd1 > div[style]")
        style = str(cover.get("style", "")) if cover is not None else ""
        match = re.search(r"url\(\s*(['\"]?)(.*?)\1\s*\)", style, re.IGNORECASE)
        if match and match.group(2).strip():
            image_url = urljoin(page_url, match.group(2).strip())

    return GalleryPreview(
        gallery_name=gallery_text or english_text or "Unknown",
        english_name=english_text or gallery_text or "Unknown",
        language=details.get("language") or "Unknown",
        file_size=details.get("file size") or "Unknown",
        length=details.get("length") or "Unknown",
        image_url=image_url,
    )


def gallery_confirmation_caption(
    preview: GalleryPreview, gallery_url: str, archive_label: str
) -> str:
    """Build a bounded Telegram photo caption with the requested metadata."""
    def shortened(value: str, limit: int = 280) -> str:
        return value if len(value) <= limit else f"{value[: limit - 1]}…"

    caption = (
        "Download this gallery?\n\n"
        f"Gallery name: {shortened(preview.gallery_name)}\n"
        f"English name: {shortened(preview.english_name)}\n"
        f"Language: {preview.language}\n"
        f"File size: {preview.file_size}\n"
        f"Length: {preview.length}\n"
        f"Archive: {archive_label}\n\n"
        f"{gallery_url}"
    )
    if len(caption) <= MAX_TELEGRAM_CAPTION_CHARS:
        return caption
    return f"{caption[: MAX_TELEGRAM_CAPTION_CHARS - 1]}…"


class ArchiveClient:
    def __init__(
        self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self.settings = settings
        self.transport = transport
        LOG.info(
            "archive step=client_initialized transport=%s archive_type=%s",
            "custom" if transport is not None else "network",
            settings.archive_type,
        )

    def _client(self) -> httpx.AsyncClient:
        cookies = parse_cookie_header(self.settings.cookie_header)
        LOG.info(
            "archive step=http_client_create cookie_names=%s",
            ",".join(sorted(cookies)),
        )
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

    async def gallery_preview(self, raw_url: str) -> GalleryPreview:
        """Fetch gallery metadata and its cover through the authenticated session."""
        host, gid, gallery_token = parse_gallery_url(raw_url)
        validate_cookie_header(self.settings.cookie_header, host)
        gallery_url = f"https://{host}/g/{gid}/{gallery_token}/"
        LOG.info("gallery_preview step=page_request_start host=%s", host)

        async with self._client() as client:
            page = await self._request(client, "GET", gallery_url)
            try:
                page_html = await self._read_html(page)
                self._raise_for_site_error(page, page_html)
                preview = gallery_preview_from_html(page_html, gallery_url)
                LOG.info(
                    "gallery_preview step=metadata_parsed image_present=%s",
                    preview.image_url is not None,
                )
            finally:
                await page.aclose()

            if preview.image_url is None:
                return preview

            try:
                image_response = await self._request(
                    client,
                    "GET",
                    preview.image_url,
                    allowed_hosts=DEFAULT_GALLERY_IMAGE_HOSTS,
                    headers={"Referer": gallery_url},
                )
                try:
                    image = await self._read_gallery_image(image_response)
                finally:
                    await image_response.aclose()
            except (httpx.HTTPError, RuntimeError, ValueError) as exc:
                LOG.warning(
                    "gallery_preview step=image_fetch_failed error_type=%s error=%s",
                    type(exc).__name__,
                    exc,
                )
                return preview

            LOG.info(
                "gallery_preview step=image_fetch_complete bytes=%s",
                len(image) if image is not None else 0,
            )
            return replace(preview, image=image)

    @staticmethod
    async def _read_gallery_image(response: httpx.Response) -> bytes | None:
        response.raise_for_status()
        content_type = response.headers.get("content-type", "").lower()
        if not content_type.startswith("image/"):
            raise RuntimeError("The gallery preview was not an image.")
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > MAX_GALLERY_PREVIEW_BYTES:
                    raise RuntimeError("The gallery preview image is too large.")
            except ValueError:
                LOG.warning("Ignoring malformed gallery preview Content-Length")

        chunks: list[bytes] = []
        received = 0
        async for chunk in response.aiter_bytes():
            received += len(chunk)
            if received > MAX_GALLERY_PREVIEW_BYTES:
                raise RuntimeError("The gallery preview image is too large.")
            chunks.append(chunk)
        return b"".join(chunks) or None

    async def download(self, raw_url: str, progress: ProgressCallback) -> Path:
        host, gid, gallery_token = parse_gallery_url(raw_url)
        LOG.info("archive step=download_start host=%s", host)
        validate_cookie_header(self.settings.cookie_header, host)
        LOG.info("archive step=session_configuration_validated host=%s", host)
        gallery_url = f"https://{host}/g/{gid}/{gallery_token}/"
        archiver_url = f"https://{host}/archiver.php?gid={gid}&token={gallery_token}"
        self.settings.download_dir.mkdir(parents=True, exist_ok=True)
        LOG.info("archive step=download_directory_ready")

        async with self._client() as client:
            LOG.info("archive step=initial_archiver_request_start host=%s", host)
            page = await self._request(
                client, "GET", archiver_url, headers={"Referer": gallery_url}
            )
            log_response_step("initial_archiver_response", page)
            page_html = await self._read_html(page)
            log_response_step("initial_archiver_html_read", page, html=page_html)
            self._raise_for_site_error(page, page_html)
            LOG.info("archive step=initial_archiver_page_validated")
            response = await self._submit_archive_request(
                client, page_html, archiver_url, gallery_url
            )
            log_response_step("initial_unlock_response", response)
            await page.aclose()
            LOG.info("archive step=initial_archiver_response_closed")
            preparation_started_at = time.monotonic()
            deadline = preparation_started_at + self.settings.wait_seconds
            check_count = 0
            LOG.info(
                "archive step=preparation_started wait_seconds=%s poll_seconds=%s",
                self.settings.wait_seconds,
                ARCHIVE_POLL_SECONDS,
            )

            while True:
                log_response_step(
                    "preparation_response_received",
                    response,
                    check_count=check_count,
                )
                if is_archive_response(response):
                    LOG.info(
                        "archive step=stage_2_entered check=%s",
                        check_count,
                    )
                    return await self._save_response(response, gid, progress)

                response_html = await self._read_html(response)
                log_response_step(
                    "preparation_html_read",
                    response,
                    html=response_html,
                    check_count=check_count,
                )
                self._raise_for_site_error(response, response_html)
                LOG.info(
                    "archive step=preparation_response_validated check=%s",
                    check_count,
                )
                link = archive_link_from_html(
                    response_html,
                    str(response.url),
                    self.settings.archive_download_hosts,
                )
                if link:
                    LOG.info(
                        "archive step=next_link_found check=%s location=%s",
                        check_count,
                        safe_url_for_log(link),
                    )
                    referer = str(response.url)
                    await response.aclose()
                    LOG.info(
                        "archive step=preparation_response_closed check=%s",
                        check_count,
                    )
                    response = await self._request(
                        client,
                        "GET",
                        link,
                        headers={"Referer": referer},
                    )
                    continue

                now = time.monotonic()
                if now >= deadline:
                    LOG.error(
                        "archive step=preparation_deadline_reached check=%s elapsed_seconds=%s",
                        check_count,
                        int(now - preparation_started_at),
                    )
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
                LOG.info(
                    "archive step=preparation_progress_sent check=%s elapsed_seconds=%s next_check_seconds=%s",
                    check_count,
                    int(now - preparation_started_at),
                    next_check_seconds,
                )
                await response.aclose()
                LOG.info(
                    "archive step=preparation_response_closed check=%s",
                    check_count,
                )
                await asyncio.sleep(next_check_seconds)
                LOG.info(
                    "archive step=preparation_poll_start check=%s",
                    check_count,
                )
                response = await self._submit_archive_request(
                    client, page_html, archiver_url, gallery_url
                )

    async def _request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        *,
        allowed_hosts: frozenset[str] | None = None,
        **kwargs,
    ) -> httpx.Response:
        """Send a streamed request with safe redirects and bounded GET retries."""
        trusted_hosts = allowed_hosts or self.settings.archive_download_hosts
        current_method = method.upper()
        current_url = validate_outbound_url(url, trusted_hosts)
        current_kwargs = dict(kwargs)
        LOG.info(
            "http step=request_start method=%s location=%s",
            current_method,
            safe_url_for_log(current_url),
        )

        for redirect_count in range(6):
            response = await self._send_with_retries(
                client, current_method, current_url, current_kwargs
            )
            LOG.info(
                "http step=response_received method=%s location=%s status=%s redirect_count=%s",
                current_method,
                safe_url_for_log(str(response.url)),
                response.status_code,
                redirect_count,
            )
            if response.status_code not in {301, 302, 303, 307, 308}:
                return response
            location = response.headers.get("location")
            if not location:
                LOG.warning("http step=redirect_missing_location status=%s", response.status_code)
                return response
            next_url = validate_outbound_url(
                urljoin(str(response.url), location),
                trusted_hosts,
            )
            LOG.info(
                "http step=redirect_follow status=%s next_location=%s",
                response.status_code,
                safe_url_for_log(next_url),
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
            LOG.info(
                "http step=send_attempt method=%s location=%s attempt=%s max_attempts=%s",
                method,
                safe_url_for_log(url),
                attempt + 1,
                attempts,
            )
            try:
                request = client.build_request(method, url, **request_kwargs)
                response = await client.send(request, stream=True)
            except httpx.TransportError as exc:
                LOG.warning(
                    "http step=transport_error method=%s location=%s attempt=%s error_type=%s",
                    method,
                    safe_url_for_log(url),
                    attempt + 1,
                    type(exc).__name__,
                )
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
            LOG.warning(
                "http step=retryable_response status=%s attempt=%s delay_seconds=%s",
                response.status_code,
                attempt + 1,
                delay,
            )
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
        LOG.info(
            "archive step=html_read_start location=%s declared_bytes=%s",
            safe_url_for_log(str(response.url)),
            content_length or "unknown",
        )
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
        decoded = bytes(body).decode(encoding, errors="replace")
        LOG.info(
            "archive step=html_read_complete location=%s received_bytes=%s encoding=%s",
            safe_url_for_log(str(response.url)),
            len(body),
            encoding,
        )
        return decoded

    async def _submit_archive_request(
        self,
        client: httpx.AsyncClient,
        page_html: str,
        archiver_url: str,
        gallery_url: str,
    ) -> httpx.Response:
        LOG.info("archive step=unlock_form_scan_start")
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
                LOG.info("archive step=login_form_skipped")
                continue
            if parsed_action.path.lower().endswith("/archiver.php"):
                form = candidate
                action = candidate_action
                LOG.info(
                    "archive step=unlock_form_selected action=%s",
                    safe_url_for_log(candidate_action),
                )
                break
        if not form:
            if login_form_found:
                LOG.error("archive step=unlock_form_missing reason=login_form")
                raise RuntimeError(
                    "The configured session is not logged in or has expired. Refresh EH_COOKIE."
                )
            LOG.error("archive step=unlock_form_missing reason=no_archive_form")
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
        LOG.info(
            "archive step=unlock_submit method=POST action=%s archive_type=%s encoding=multipart",
            safe_url_for_log(action),
            self.settings.archive_type,
        )
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
        LOG.info(
            "archive step=site_error_check status=%s location=%s",
            response.status_code,
            safe_url_for_log(str(response.url)),
        )
        if response.status_code in {401, 403} and (
            "act=login" in parsed_url.query.lower()
            or (
                (parsed_url.hostname or "").lower() == "forums.e-hentai.org"
                and parsed_url.path.lower().endswith("/index.php")
            )
        ):
            LOG.error("archive step=site_error_detected category=expired_session")
            raise RuntimeError(
                "The configured session is not logged in or has expired. Refresh EH_COOKIE."
            )
        response.raise_for_status()
        text = response_html.lower()
        if any(marker in text for marker in AUTH_FAILURE_MARKERS):
            LOG.error("archive step=site_error_detected category=auth_marker")
            raise RuntimeError(
                "The configured session is not logged in or has expired. Refresh EH_COOKIE."
            )
        if "sad panda" in text or (
            "exhentai.org" in str(response.url) and "restricted" in text
        ):
            LOG.error("archive step=site_error_detected category=access_restricted")
            raise RuntimeError(
                "This account cannot access ExHentai from the current network/session."
            )
        if "insufficient funds" in text or "insufficient gp" in text:
            LOG.error("archive step=site_error_detected category=insufficient_funds")
            raise RuntimeError(
                "The account does not have enough archive points for this download."
            )
        LOG.info("archive step=site_error_check_passed")

    def _storage_budget(self) -> int:
        LOG.info("archive step=storage_budget_calculation_start")
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
            LOG.error(
                "archive step=storage_budget_exhausted quota_remaining=%s disk_remaining=%s",
                quota_remaining,
                disk_remaining,
            )
            raise RuntimeError(
                "Download storage quota or minimum free-disk reserve has been reached."
            )
        LOG.info(
            "archive step=storage_budget_ready budget_bytes=%s quota_remaining=%s disk_remaining=%s",
            budget,
            quota_remaining,
            disk_remaining,
        )
        return budget

    def _unique_destination(self, filename: str, gid: str) -> Path:
        destination = self.settings.download_dir / filename
        if not destination.exists():
            LOG.info("archive step=destination_available collision=false")
            return destination
        LOG.warning("archive step=destination_collision collision=true")
        return (
            self.settings.download_dir
            / f"{destination.stem}-{gid}-{uuid4().hex[:8]}{destination.suffix}"
        )

    def _commit_temporary(self, temporary: Path, filename: str, gid: str) -> Path:
        """Publish a complete file atomically without overwriting any path."""
        LOG.info("archive step=atomic_commit_start")
        while True:
            destination = self._unique_destination(filename, gid)
            try:
                os.link(temporary, destination)
            except FileExistsError:
                LOG.warning("archive step=atomic_commit_collision retry=true")
                continue
            temporary.unlink()
            LOG.info("archive step=atomic_commit_complete")
            return destination

    async def _save_response(
        self, response: httpx.Response, gid: str, progress: ProgressCallback
    ) -> Path:
        temporary: Path | None = None
        LOG.info(
            "archive step=save_response_start location=%s",
            safe_url_for_log(str(response.url)),
        )
        try:
            budget = self._storage_budget()
            length_header = response.headers.get("content-length")
            total_bytes: int | None = None
            if length_header:
                try:
                    parsed_length = int(length_header)
                    if parsed_length > budget:
                        LOG.error(
                            "archive step=declared_size_rejected declared_bytes=%s budget_bytes=%s",
                            parsed_length,
                            budget,
                        )
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
            LOG.info(
                "archive step=temporary_file_planned total_bytes=%s budget_bytes=%s",
                total_bytes if total_bytes is not None else "unknown",
                budget,
            )
            written = 0
            last_reported_bytes = 0
            last_reported_percentage = 0
            last_progress_at = time.monotonic()
            await progress(download_progress_message(filename, 0, total_bytes))
            LOG.info("archive step=download_progress_sent written_bytes=0")
            with temporary.open("xb") as file_handle:
                LOG.info("archive step=temporary_file_opened")
                async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                    written += len(chunk)
                    LOG.info(
                        "archive step=download_chunk_received chunk_bytes=%s written_bytes=%s",
                        len(chunk),
                        written,
                    )
                    if written > budget:
                        LOG.error(
                            "archive step=stream_size_rejected written_bytes=%s budget_bytes=%s",
                            written,
                            budget,
                        )
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
                        LOG.info(
                            "archive step=download_progress_sent written_bytes=%s percentage=%s",
                            written,
                            current_percentage if current_percentage is not None else "unknown",
                        )
                file_handle.flush()
                LOG.info("archive step=temporary_file_flushed")
                os.fsync(file_handle.fileno())
                LOG.info("archive step=temporary_file_synced")

            if written != last_reported_bytes:
                await progress(
                    download_progress_message(filename, written, total_bytes)
                )
            await progress(
                f"🔎 Download received: {filename}\n"
                f"{format_bytes(written)} — validating archive…"
            )
            LOG.info(
                "archive step=archive_validation_start written_bytes=%s",
                written,
            )

            detected_suffix = archive_format(temporary)
            if detected_suffix is None:
                LOG.error("archive step=archive_validation_failed reason=signature")
                raise RuntimeError(
                    "The downloaded response was not a recognized ZIP, RAR, or 7z archive."
                )
            declared_suffix = Path(filename).suffix.lower()
            if declared_suffix in {".zip", ".rar", ".7z"}:
                if declared_suffix != detected_suffix:
                    filename = f"{Path(filename).stem}{detected_suffix}"
            else:
                filename = f"{filename}{detected_suffix}"
            LOG.info(
                "archive step=archive_validation_passed detected_format=%s",
                detected_suffix.removeprefix("."),
            )
            return self._commit_temporary(temporary, filename, gid)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
                LOG.info("archive step=temporary_cleanup_complete")
            await response.aclose()
            LOG.info("archive step=download_response_closed")


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
        LOG.info("bot step=service_initialized queue_capacity=%s", settings.queue_size)

    def authorized(self, update: Update) -> bool:
        user = update.effective_user
        chat = update.effective_chat
        authorized = (
            user is not None
            and user.id in self.settings.allowed_user_ids
            and chat is not None
            and chat.type == ChatType.PRIVATE
        )
        LOG.info(
            "bot step=authorization_checked authorized=%s user_present=%s chat_present=%s private_chat=%s",
            authorized,
            user is not None,
            chat is not None,
            chat is not None and chat.type == ChatType.PRIVATE,
        )
        return authorized

    async def post_init(self, application: Application) -> None:
        LOG.info("bot step=post_init_start")
        self.worker_task = asyncio.create_task(self._worker(), name="archive-worker")
        LOG.info("bot step=worker_task_created")

    async def post_shutdown(self, application: Application) -> None:
        LOG.info("bot step=post_shutdown_start worker_present=%s", self.worker_task is not None)
        if self.worker_task is None:
            return
        self.worker_task.cancel()
        LOG.info("bot step=worker_cancel_requested")
        with suppress(asyncio.CancelledError):
            await self.worker_task
        LOG.info("bot step=post_shutdown_complete")

    async def _safe_edit(self, notice: Message, message: str) -> None:
        LOG.info("telegram step=notice_edit_start message_chars=%s", len(message))
        for attempt in range(3):
            try:
                photo = getattr(notice, "photo", None)
                if isinstance(photo, (list, tuple)) and photo:
                    await notice.edit_caption(caption=message, reply_markup=None)
                else:
                    await notice.edit_text(message, reply_markup=None)
                LOG.info(
                    "telegram step=notice_edit_complete attempt=%s",
                    attempt + 1,
                )
                return
            except RetryAfter as exc:
                retry_after = exc.retry_after
                delay = (
                    retry_after.total_seconds()
                    if hasattr(retry_after, "total_seconds")
                    else float(retry_after)
                )
                LOG.warning(
                    "telegram step=notice_edit_rate_limited attempt=%s delay_seconds=%s",
                    attempt + 1,
                    delay,
                )
                await asyncio.sleep(min(max(delay, 0.0), 30.0))
            except NetworkError:
                LOG.warning(
                    "telegram step=notice_edit_network_error attempt=%s",
                    attempt + 1,
                )
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
        LOG.info(
            "telegram step=callback_answer_start has_message=%s show_alert=%s",
            message is not None,
            show_alert,
        )
        try:
            await query.answer(message, show_alert=show_alert)
            LOG.info("telegram step=callback_answer_complete")
        except TelegramError:
            LOG.warning("Could not answer Telegram callback query", exc_info=True)

    def _prune_pending_downloads(self) -> None:
        before = len(self.pending_downloads)
        cutoff = time.monotonic() - CONFIRMATION_TTL_SECONDS
        expired = [
            request_id
            for request_id, pending in self.pending_downloads.items()
            if pending.created_at < cutoff
        ]
        for request_id in expired:
            self.pending_downloads.pop(request_id, None)
        LOG.info(
            "bot step=pending_confirmations_pruned before=%s expired=%s remaining=%s",
            before,
            len(expired),
            len(self.pending_downloads),
        )

    async def _worker(self) -> None:
        LOG.info("worker step=loop_started")
        while True:
            LOG.info("worker step=waiting_for_job queued=%s", self.queue.qsize())
            job = await self.queue.get()
            self.active_job = job
            LOG.info("worker step=job_started queued_remaining=%s", self.queue.qsize())

            async def progress(message: str, notice: Message = job.notice) -> None:
                LOG.info("worker step=progress_callback message_chars=%s", len(message))
                await self._safe_edit(notice, message)

            try:
                archive = await self.client.download(job.url, progress)
                LOG.info(
                    "worker step=archive_download_complete size_bytes=%s",
                    archive.stat().st_size,
                )
                await self._safe_edit(
                    job.notice,
                    f"✅ Download completed successfully\n"
                    f"File: {archive.name}\n"
                    f"Size: {format_bytes(archive.stat().st_size)}\n"
                    f"Saved to: {archive.parent}",
                )
            except asyncio.CancelledError:
                LOG.warning("worker step=job_cancelled")
                await self._safe_edit(
                    job.notice, "Download interrupted because the bot is stopping."
                )
                raise
            except (httpx.HTTPError, RuntimeError, ValueError) as exc:
                LOG.warning(
                    "worker step=job_failed error_type=%s error=%s",
                    type(exc).__name__,
                    exc,
                )
                await self._safe_edit(job.notice, f"❌ Download failed\n{exc}")
            except Exception:
                LOG.exception("worker step=job_failed_unexpected")
                await self._safe_edit(
                    job.notice,
                    "❌ Download failed unexpectedly\nCheck the bot logs for details.",
                )
            finally:
                self.active_job = None
                self.queue.task_done()
                LOG.info(
                    "worker step=job_finalized queued=%s",
                    self.queue.qsize(),
                )

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        LOG.info("bot step=start_command_received")
        if not self.authorized(update):
            LOG.info("bot step=start_command_ignored reason=unauthorized")
            return
        await update.effective_message.reply_text(
            "Send or forward an E-Hentai or ExHentai gallery URL.\n"
            "I’ll ask for confirmation before queueing it.\n"
            "Use /status to check configuration and queue state."
        )

    async def whoami(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        LOG.info("bot step=whoami_command_received")
        if not self.authorized(update):
            LOG.info("bot step=whoami_command_ignored reason=unauthorized")
            return
        await update.effective_message.reply_text(
            f"Your Telegram user ID: {update.effective_user.id}"
        )

    async def status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        LOG.info("bot step=status_command_received")
        if not self.authorized(update):
            LOG.info("bot step=status_command_ignored reason=unauthorized")
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
        LOG.info("bot step=gallery_message_received")
        if not self.authorized(update):
            LOG.info("bot step=gallery_message_ignored reason=unauthorized")
            return
        message = update.effective_message
        text = message.text or message.caption or ""
        gallery_url = extract_gallery_url(text)
        if gallery_url is None:
            LOG.info("bot step=gallery_message_rejected reason=no_valid_url")
            await message.reply_text(
                "I couldn’t find a valid E-Hentai or ExHentai gallery URL in that message."
            )
            return

        LOG.info(
            "bot step=gallery_url_accepted host=%s",
            urlparse(gallery_url).hostname,
        )
        await message.reply_chat_action(ChatAction.UPLOAD_PHOTO)
        self._prune_pending_downloads()
        if len(self.pending_downloads) >= self.settings.queue_size:
            LOG.warning("bot step=confirmation_rejected reason=capacity")
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
        try:
            preview = await self.client.gallery_preview(gallery_url)
            LOG.info(
                "bot step=gallery_preview_loaded image_present=%s",
                preview.image is not None,
            )
        except (httpx.HTTPError, RuntimeError, ValueError) as exc:
            LOG.warning(
                "bot step=gallery_preview_failed error_type=%s error=%s",
                type(exc).__name__,
                exc,
            )
            preview = GalleryPreview(
                gallery_name="Unavailable",
                english_name="Unavailable",
                language="Unknown",
                file_size="Unknown",
                length="Unknown",
                image_url=None,
            )

        caption = gallery_confirmation_caption(preview, gallery_url, archive_label)
        if preview.image is not None:
            try:
                await message.reply_photo(
                    photo=InputFile(preview.image, filename="gallery-preview"),
                    caption=caption,
                    reply_markup=keyboard,
                )
                LOG.info("bot step=confirmation_photo_sent")
            except TelegramError:
                LOG.warning(
                    "bot step=confirmation_photo_failed fallback=text",
                    exc_info=True,
                )
                await message.reply_text(caption, reply_markup=keyboard)
        else:
            await message.reply_text(caption, reply_markup=keyboard)
        self.pending_downloads[request_id] = PendingDownload(
            url=gallery_url,
            user_id=update.effective_user.id,
            created_at=time.monotonic(),
        )
        LOG.info(
            "bot step=confirmation_created pending=%s",
            len(self.pending_downloads),
        )

    async def confirm_download(
        self, update: Update, context: ContextTypes.DEFAULT_TYPE
    ) -> None:
        LOG.info("bot step=confirmation_callback_received")
        if not self.authorized(update) or update.callback_query is None:
            LOG.info("bot step=confirmation_callback_ignored reason=unauthorized_or_missing")
            return
        query = update.callback_query
        data = query.data or ""
        try:
            _prefix, action, request_id = data.split(":", 2)
        except ValueError:
            LOG.warning("bot step=confirmation_rejected reason=malformed_callback")
            await self._safe_answer(query, "Invalid download request.", show_alert=True)
            return
        if action not in {"confirm", "cancel"}:
            LOG.warning("bot step=confirmation_rejected reason=invalid_action")
            await self._safe_answer(query, "Invalid download request.", show_alert=True)
            return

        self._prune_pending_downloads()
        pending = self.pending_downloads.get(request_id)
        if pending is None:
            LOG.info("bot step=confirmation_rejected reason=expired")
            await self._safe_answer(
                query, "This confirmation has expired.", show_alert=True
            )
            if query.message is not None:
                await self._safe_edit(
                    query.message, "This download confirmation has expired."
                )
            return
        if pending.user_id != update.effective_user.id:
            LOG.warning("bot step=confirmation_rejected reason=wrong_user")
            await self._safe_answer(
                query, "This confirmation belongs to another user.", show_alert=True
            )
            return

        self.pending_downloads.pop(request_id, None)
        await self._safe_answer(query)
        if query.message is None:
            LOG.warning("bot step=confirmation_stopped reason=missing_message")
            return
        if action == "cancel":
            LOG.info("bot step=confirmation_cancelled")
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
            LOG.warning("bot step=queue_rejected reason=full")
            await self._safe_edit(
                query.message, "The download queue is full; try again later."
            )
            return
        LOG.info(
            "bot step=job_queued position=%s queued=%s",
            queue_position,
            self.queue.qsize(),
        )
        await self._safe_edit(
            query.message, f"⏳ Confirmed and queued at position {queue_position}."
        )


def main() -> None:
    settings = Settings.from_env()
    configure_logging(settings)
    LOG.info("startup step=settings_loaded")
    enable_function_call_logging()
    LOG.info("startup step=service_construction_start")
    service = BotService(settings)
    LOG.info("startup step=telegram_application_build_start")
    app = (
        Application.builder()
        .token(settings.token)
        .concurrent_updates(8)
        .post_init(service.post_init)
        .post_shutdown(service.post_shutdown)
        .build()
    )
    LOG.info("startup step=telegram_application_built")
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
    LOG.info("startup step=handlers_registered")
    LOG.info("Bot starting; destination is %s", settings.download_dir)
    LOG.info("startup step=polling_start")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
