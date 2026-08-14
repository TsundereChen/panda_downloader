"""Telegram-controlled archive downloader for E-Hentai and ExHentai.

The bot requests the site's own archive, then saves the completed archive to a
local directory. It deliberately does not scrape individual gallery images.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from telegram import Update
from telegram.constants import ChatAction
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters

LOG = logging.getLogger(__name__)
GALLERY_RE: Final = re.compile(
    r"^https?://(?P<host>e-hentai\.org|exhentai\.org)/g/(?P<gid>\d+)/(?P<token>[0-9a-fA-F]+)/?",
    re.IGNORECASE,
)
SAFE_FILENAME_RE: Final = re.compile(r"[^\w.()\[\] -]+", re.UNICODE)
AUTH_FAILURE_MARKERS: Final = (
    "you are not logged in",
    "please log in",
    "invalid login",
    "log in to continue",
)


@dataclass(frozen=True)
class Settings:
    token: str
    allowed_user_ids: frozenset[int]
    access_password: str
    cookie_header: str
    download_dir: Path
    archive_type: str
    max_archive_bytes: int
    wait_seconds: int

    @classmethod
    def from_env(cls) -> "Settings":
        load_dotenv()
        token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise RuntimeError("TELEGRAM_BOT_TOKEN is required")
        archive_type = os.getenv("ARCHIVE_TYPE", "org").strip().lower()
        if archive_type not in {"org", "res"}:
            raise RuntimeError("ARCHIVE_TYPE must be org or res")
        try:
            allowed = frozenset(
                int(item.strip())
                for item in os.getenv("ALLOWED_TELEGRAM_USER_IDS", "").split(",")
                if item.strip()
            )
            max_gib = float(os.getenv("MAX_ARCHIVE_GIB", "8"))
            wait_minutes = float(os.getenv("ARCHIVE_WAIT_MINUTES", "30"))
        except ValueError as exc:
            raise RuntimeError("Invalid numeric setting in .env") from exc
        if max_gib <= 0 or wait_minutes <= 0:
            raise RuntimeError("MAX_ARCHIVE_GIB and ARCHIVE_WAIT_MINUTES must be positive")
        return cls(
            token=token,
            allowed_user_ids=allowed,
            access_password=os.getenv("BOT_ACCESS_PASSWORD", ""),
            cookie_header=os.getenv("EH_COOKIE", ""),
            download_dir=Path(os.getenv("DOWNLOAD_DIR", "./downloads")).expanduser().resolve(),
            archive_type=archive_type,
            max_archive_bytes=int(max_gib * 1024**3),
            wait_seconds=int(wait_minutes * 60),
        )


def parse_gallery_url(raw_url: str) -> tuple[str, str, str]:
    """Return (host, gid, token), accepting only supported canonical URLs."""
    match = GALLERY_RE.match(raw_url.strip())
    if not match:
        raise ValueError("Send a full E-Hentai or ExHentai gallery URL (…/g/<id>/<token>/).")
    return match.group("host").lower(), match.group("gid"), match.group("token").lower()


def parse_cookie_header(header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in header.split(";"):
        name, sep, value = part.strip().partition("=")
        if sep and name and value:
            cookies[name] = value
    return cookies


def safe_filename(name: str, fallback: str) -> str:
    cleaned = SAFE_FILENAME_RE.sub("_", name).strip(" ._")
    return (cleaned or fallback)[:180]


def filename_from_response(response: httpx.Response, fallback: str) -> str:
    disposition = response.headers.get("content-disposition", "")
    match = re.search(r"filename\*?=(?:UTF-8''|\")?([^\";]+)", disposition, re.I)
    return safe_filename(match.group(1) if match else fallback, fallback)


def is_archive_response(response: httpx.Response) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    disposition = response.headers.get("content-disposition", "").lower()
    return "attachment" in disposition or any(kind in content_type for kind in ("zip", "rar", "7z", "octet-stream"))


def archive_link_from_html(html: str, page_url: str) -> str | None:
    """Find the completed-download link without trusting arbitrary page links."""
    soup = BeautifulSoup(html, "html.parser")
    for anchor in soup.select("a[href]"):
        href = urljoin(page_url, anchor["href"])
        parsed = urlparse(href)
        text = anchor.get_text(" ", strip=True).lower()
        if parsed.scheme != "https":
            continue
        if any(word in text for word in ("download", "click here", "archive")) or re.search(
            r"\.(zip|rar|7z)(?:$|[?#])", parsed.path, re.I
        ):
            return href
    return None


class ArchiveClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _client(self) -> httpx.AsyncClient:
        cookies = parse_cookie_header(self.settings.cookie_header)
        jar = httpx.Cookies()
        # Cookie header strings lose domain metadata. Set credentials for both
        # supported hosts; only HTTPS requests to these hosts receive them.
        for name, value in cookies.items():
            jar.set(name, value, domain=".e-hentai.org", path="/")
            jar.set(name, value, domain=".exhentai.org", path="/")
        return httpx.AsyncClient(
            cookies=jar,
            follow_redirects=True,
            timeout=httpx.Timeout(connect=20, read=90, write=30, pool=30),
            headers={"User-Agent": "Mozilla/5.0 (compatible; PersonalArchiveBot/1.0)"},
        )

    async def download(self, raw_url: str, progress) -> Path:
        if not self.settings.cookie_header:
            raise RuntimeError("EH_COOKIE is not configured. Add a logged-in browser Cookie header to .env.")
        host, gid, gallery_token = parse_gallery_url(raw_url)
        gallery_url = f"https://{host}/g/{gid}/{gallery_token}/"
        archiver_url = f"https://{host}/archiver.php?gid={gid}&token={gallery_token}"
        self.settings.download_dir.mkdir(parents=True, exist_ok=True)

        async with self._client() as client:
            page = await self._request(client, "GET", archiver_url, headers={"Referer": gallery_url})
            await page.aread()  # archive page is small HTML; binary replies stay streamed below
            self._raise_for_site_error(page)
            response = await self._submit_archive_request(client, page, archiver_url, gallery_url)
            await page.aclose()
            deadline = time.monotonic() + self.settings.wait_seconds
            announced_wait = False

            while True:
                if is_archive_response(response):
                    return await self._save_response(response, gid, progress)

                await response.aread()
                self._raise_for_site_error(response)
                link = archive_link_from_html(response.text, str(response.url))
                if link:
                    await response.aclose()
                    response = await self._request(client, "GET", link, headers={"Referer": gallery_url})
                    continue

                if time.monotonic() >= deadline:
                    raise RuntimeError("The archive was not ready before the configured wait limit.")
                if not announced_wait:
                    await progress("The site is preparing the archive; I’ll keep checking.")
                    announced_wait = True
                await asyncio.sleep(15)
                # The archive page exposes the completed link when its queue is done.
                await response.aclose()
                response = await self._request(client, "GET", archiver_url, headers={"Referer": gallery_url})

    @staticmethod
    async def _request(client: httpx.AsyncClient, method: str, url: str, **kwargs) -> httpx.Response:
        """Keep possible archives streamed instead of buffering them in RAM."""
        request = client.build_request(method, url, **kwargs)
        return await client.send(request, stream=True)

    async def _submit_archive_request(
        self, client: httpx.AsyncClient, page: httpx.Response, archiver_url: str, gallery_url: str
    ) -> httpx.Response:
        soup = BeautifulSoup(page.text, "html.parser")
        form = soup.find("form")
        if not form:
            raise RuntimeError("Could not find the archive form. Check that the account is eligible for archive downloads.")
        data = {
            input_tag.get("name"): input_tag.get("value", "")
            for input_tag in form.select("input[name]")
            if input_tag.get("type", "").lower() not in {"submit", "button"}
        }
        data["dltype"] = self.settings.archive_type
        submit = form.select_one('input[type="submit"][name], button[type="submit"][name]')
        if submit and submit.get("name"):
            # The server uses this field to distinguish a confirmed archive
            # request from merely opening the options form.
            data[submit["name"]] = submit.get("value", "Download")
        action = urljoin(archiver_url, form.get("action") or archiver_url)
        return await self._request(client, "POST", action, data=data, headers={"Referer": gallery_url})

    def _raise_for_site_error(self, response: httpx.Response) -> None:
        response.raise_for_status()
        if is_archive_response(response):
            return
        text = response.text.lower()
        if any(marker in text for marker in AUTH_FAILURE_MARKERS):
            raise RuntimeError("The configured session is not logged in or has expired. Refresh EH_COOKIE.")
        if "sad panda" in text or "exhentai.org" in str(response.url) and "restricted" in text:
            raise RuntimeError("This account cannot access ExHentai from the current network/session.")
        if "insufficient funds" in text or "insufficient gp" in text:
            raise RuntimeError("The account does not have enough archive points for this download.")

    async def _save_response(self, response: httpx.Response, gid: str, progress) -> Path:
        length_header = response.headers.get("content-length")
        if length_header:
            try:
                if int(length_header) > self.settings.max_archive_bytes:
                    raise RuntimeError("The archive exceeds MAX_ARCHIVE_GIB and was not saved.")
            except ValueError:
                LOG.warning("Ignoring malformed Content-Length header: %r", length_header)
        filename = filename_from_response(response, f"ehentai-{gid}.zip")
        destination = self.settings.download_dir / filename
        # Never silently overwrite a previously downloaded archive.
        if destination.exists():
            destination = self.settings.download_dir / f"{destination.stem}-{int(time.time())}{destination.suffix}"
        written = 0
        await progress(f"Downloading `{destination.name}`…")
        with destination.open("xb") as file_handle:
            async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                written += len(chunk)
                if written > self.settings.max_archive_bytes:
                    file_handle.close()
                    destination.unlink(missing_ok=True)
                    raise RuntimeError("The archive exceeded MAX_ARCHIVE_GIB; the partial file was removed.")
                file_handle.write(chunk)
        return destination


class BotService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.client = ArchiveClient(settings)
        self.logged_in_users: set[int] = set()
        self.jobs = asyncio.Semaphore(1)  # avoids concurrent archive quota/queue surprises

    def allowed(self, user_id: int | None) -> bool:
        return user_id is not None and (not self.settings.allowed_user_ids or user_id in self.settings.allowed_user_ids)

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.allowed(update.effective_user.id if update.effective_user else None):
            await update.effective_message.reply_text("This bot is private.")
            return
        await update.effective_message.reply_text(
            "Send /login <bot password>, then forward or paste an E-Hentai or ExHentai gallery URL.\n"
            "Use /status to check configuration; /whoami shows your Telegram ID."
        )

    async def whoami(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        await update.effective_message.reply_text(f"Your Telegram user ID: {update.effective_user.id}")

    async def login(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.allowed(update.effective_user.id if update.effective_user else None):
            await update.effective_message.reply_text("This bot is private.")
            return
        supplied = " ".join(context.args)
        if not self.settings.access_password:
            await update.effective_message.reply_text("BOT_ACCESS_PASSWORD is not configured on the server.")
        elif secrets.compare_digest(supplied, self.settings.access_password):
            self.logged_in_users.add(update.effective_user.id)
            await update.effective_message.reply_text("Logged in for this bot session. Send a gallery URL when ready.")
        else:
            await update.effective_message.reply_text("Login failed.")

    async def logout(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        self.logged_in_users.discard(update.effective_user.id)
        await update.effective_message.reply_text("Logged out.")

    async def status(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        if not self.allowed(update.effective_user.id if update.effective_user else None):
            await update.effective_message.reply_text("This bot is private.")
            return
        cookie_state = "configured" if self.settings.cookie_header else "missing"
        await update.effective_message.reply_text(
            f"Site session: {cookie_state}\nDestination: {self.settings.download_dir}\nFormat: {self.settings.archive_type}"
        )

    async def gallery_message(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        user_id = update.effective_user.id if update.effective_user else None
        if not self.allowed(user_id):
            await update.effective_message.reply_text("This bot is private.")
            return
        if user_id not in self.logged_in_users:
            await update.effective_message.reply_text("Use /login first.")
            return
        text = update.effective_message.text or update.effective_message.caption or ""
        urls = re.findall(r"https?://[^\s]+", text)
        if not urls:
            await update.effective_message.reply_text("I couldn’t find a URL in that message.")
            return
        try:
            parse_gallery_url(urls[0])
        except ValueError as exc:
            await update.effective_message.reply_text(str(exc))
            return
        await update.effective_message.reply_chat_action(ChatAction.TYPING)
        notice = await update.effective_message.reply_text("Queued. Requesting the site archive…")

        async def progress(message: str) -> None:
            await notice.edit_text(message)

        try:
            async with self.jobs:
                archive = await self.client.download(urls[0], progress)
            await notice.edit_text(f"Finished: `{archive.name}`\nSaved to `{archive.parent}`", parse_mode="Markdown")
        except (httpx.HTTPError, RuntimeError, ValueError) as exc:
            LOG.warning("Download failed: %s", exc)
            await notice.edit_text(f"Download failed: {exc}")
        except Exception:
            LOG.exception("Unexpected download failure")
            await notice.edit_text("Download failed unexpectedly; check the bot logs.")


def main() -> None:
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings.from_env()
    service = BotService(settings)
    app = Application.builder().token(settings.token).build()
    app.add_handler(CommandHandler("start", service.start))
    app.add_handler(CommandHandler("whoami", service.whoami))
    app.add_handler(CommandHandler("login", service.login))
    app.add_handler(CommandHandler("logout", service.logout))
    app.add_handler(CommandHandler("status", service.status))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, service.gallery_message))
    LOG.info("Bot starting; destination is %s", settings.download_dir)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
