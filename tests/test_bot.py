import asyncio
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from telegram.constants import ChatType

from bot import (
    ArchiveClient,
    ArchiveJob,
    BotService,
    Settings,
    archive_link_from_html,
    download_progress_message,
    extract_gallery_url,
    filename_from_response,
    format_bytes,
    parse_cookie_header,
    parse_gallery_url,
)
from eh_web_login import CookieCollector, cookie_header, is_ready, parse_cookie_string


def make_settings(tmp_path: Path, **overrides) -> Settings:
    values = {
        "token": "telegram-token",
        "allowed_user_ids": frozenset({123}),
        "cookie_header": "ipb_member_id=1; ipb_pass_hash=hash; igneous=gate",
        "download_dir": tmp_path,
        "archive_type": "org",
        "max_archive_bytes": 1024 * 1024,
        "max_total_bytes": 2 * 1024 * 1024,
        "min_free_bytes": 1,
        "wait_seconds": 1,
        "queue_size": 3,
        "archive_download_hosts": frozenset({"e-hentai.org", "exhentai.org"}),
    }
    values.update(overrides)
    return Settings(**values)


def fake_update(user_id: int, chat_type: str = ChatType.PRIVATE):
    message = AsyncMock()
    message.text = None
    message.caption = None
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=user_id),
        effective_chat=SimpleNamespace(type=chat_type),
        effective_message=message,
    )


def test_gallery_url_parser_accepts_both_hosts_and_query():
    assert parse_gallery_url("https://e-hentai.org/g/12/abcDEF/") == (
        "e-hentai.org",
        "12",
        "abcdef",
    )
    assert parse_gallery_url("https://exhentai.org/g/9/123abc/?p=2") == (
        "exhentai.org",
        "9",
        "123abc",
    )


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/g/12/abcdef/",
        "https://e-hentai.org/g/12/abcdef/extra",
        "https://e-hentai.org/g/12/abcdef.evil",
        "https://user@e-hentai.org/g/12/abcdef/",
    ],
)
def test_gallery_url_parser_rejects_untrusted_or_noncanonical_urls(url):
    with pytest.raises(ValueError):
        parse_gallery_url(url)


def test_extract_gallery_url_skips_other_links_and_trailing_punctuation():
    text = "See https://example.com first, then (https://e-hentai.org/g/12/abcdef/)."
    assert extract_gallery_url(text) == "https://e-hentai.org/g/12/abcdef/"


def test_cookie_header_parser_keeps_only_required_site_cookies():
    assert parse_cookie_header(
        "unrelated=one; ipb_member_id=123; ipb_pass_hash=two=three; igneous=gate"
    ) == {"ipb_member_id": "123", "ipb_pass_hash": "two=three", "igneous": "gate"}


def test_completed_link_is_resolved_and_external_link_is_rejected():
    assert (
        archive_link_from_html(
            '<a href="/archive/file.zip">Download archive</a>', "https://e-hentai.org/a"
        )
        == "https://e-hentai.org/archive/file.zip"
    )
    assert (
        archive_link_from_html(
            '<a href="https://attacker.example/file.zip">Download archive</a>',
            "https://e-hentai.org/a",
        )
        is None
    )


def test_filename_content_disposition():
    request = httpx.Request("GET", "https://example.test/file")
    response = httpx.Response(
        200,
        request=request,
        headers={"content-disposition": 'attachment; filename="hello.zip"'},
    )
    assert filename_from_response(response, "fallback.zip") == "hello.zip"


def test_settings_require_nonempty_allow_list(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("ALLOWED_TELEGRAM_USER_IDS", "")
    with pytest.raises(RuntimeError, match="at least one"):
        Settings.from_env()


def test_settings_reject_invalid_archive_host(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("ALLOWED_TELEGRAM_USER_IDS", "123")
    monkeypatch.setenv("ARCHIVE_DOWNLOAD_HOSTS", "https://bad.example")
    with pytest.raises(RuntimeError, match="hostnames"):
        Settings.from_env()


def test_only_approved_private_users_are_authorized(tmp_path):
    service = BotService(make_settings(tmp_path))
    assert service.authorized(fake_update(123))
    assert not service.authorized(fake_update(999))
    assert not service.authorized(fake_update(123, ChatType.GROUP))


def test_unauthorized_user_receives_no_response(tmp_path):
    service = BotService(make_settings(tmp_path))
    update = fake_update(999)
    asyncio.run(service.start(update, None))
    update.effective_message.reply_text.assert_not_awaited()


def test_gallery_handler_prompts_before_queueing(tmp_path):
    service = BotService(make_settings(tmp_path))
    update = fake_update(123)
    update.effective_message.text = "https://e-hentai.org/g/12/abcdef/"

    asyncio.run(service.gallery_message(update, None))

    assert service.queue.qsize() == 0
    assert len(service.pending_downloads) == 1
    prompt_call = update.effective_message.reply_text.await_args
    assert "Download this gallery?" in prompt_call.args[0]
    keyboard = prompt_call.kwargs["reply_markup"]
    assert [button.text for button in keyboard.inline_keyboard[0]] == [
        "✅ Yes, download",
        "❌ No, cancel",
    ]


def test_confirmation_queues_download(tmp_path):
    service = BotService(make_settings(tmp_path))
    message_update = fake_update(123)
    message_update.effective_message.text = "https://e-hentai.org/g/12/abcdef/"
    asyncio.run(service.gallery_message(message_update, None))
    request_id = next(iter(service.pending_downloads))

    query = AsyncMock()
    query.data = f"archive:confirm:{request_id}"
    query.message = AsyncMock()
    callback_update = fake_update(123)
    callback_update.callback_query = query
    callback_update.effective_message = query.message

    asyncio.run(service.confirm_download(callback_update, None))

    assert service.queue.qsize() == 1
    assert request_id not in service.pending_downloads
    queued = service.queue.get_nowait()
    assert queued.url == "https://e-hentai.org/g/12/abcdef/"
    assert queued.notice is query.message
    assert "Confirmed and queued" in query.message.edit_text.await_args.args[0]


def test_cancelling_confirmation_does_not_queue(tmp_path):
    service = BotService(make_settings(tmp_path))
    message_update = fake_update(123)
    message_update.effective_message.text = "https://e-hentai.org/g/12/abcdef/"
    asyncio.run(service.gallery_message(message_update, None))
    request_id = next(iter(service.pending_downloads))

    query = AsyncMock()
    query.data = f"archive:cancel:{request_id}"
    query.message = AsyncMock()
    callback_update = fake_update(123)
    callback_update.callback_query = query
    callback_update.effective_message = query.message

    asyncio.run(service.confirm_download(callback_update, None))

    assert service.queue.qsize() == 0
    assert request_id not in service.pending_downloads
    assert query.message.edit_text.await_args.args[0] == "Download cancelled."


def test_unknown_confirmation_is_reported_as_expired(tmp_path):
    service = BotService(make_settings(tmp_path))
    query = AsyncMock()
    query.data = f"archive:confirm:{'a' * 32}"
    query.message = AsyncMock()
    callback_update = fake_update(123)
    callback_update.callback_query = query
    callback_update.effective_message = query.message

    asyncio.run(service.confirm_download(callback_update, None))

    assert service.queue.qsize() == 0
    assert query.answer.await_args.args[0] == "This confirmation has expired."
    assert "expired" in query.message.edit_text.await_args.args[0]


def test_confirmation_cannot_be_used_by_another_approved_user(tmp_path):
    settings = make_settings(tmp_path, allowed_user_ids=frozenset({123, 456}))
    service = BotService(settings)
    message_update = fake_update(123)
    message_update.effective_message.text = "https://e-hentai.org/g/12/abcdef/"
    asyncio.run(service.gallery_message(message_update, None))
    request_id = next(iter(service.pending_downloads))

    query = AsyncMock()
    query.data = f"archive:confirm:{request_id}"
    query.message = AsyncMock()
    callback_update = fake_update(456)
    callback_update.callback_query = query
    callback_update.effective_message = query.message

    asyncio.run(service.confirm_download(callback_update, None))

    assert service.queue.qsize() == 0
    assert request_id in service.pending_downloads
    assert "another user" in query.answer.await_args.args[0]


def test_download_progress_formatting():
    assert format_bytes(1536) == "1.5 KiB"
    assert download_progress_message("gallery.zip", 512, 1024) == (
        "⬇️ Downloading gallery.zip\n50% — 512 B / 1.0 KiB"
    )
    assert "Received 512 B" in download_progress_message("gallery.zip", 512, None)


def test_archive_client_complete_flow(tmp_path):
    calls = []
    archive_bytes = b"PK\x03\x04" + b"archive-data"

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.method == "GET" and request.url.path == "/archiver.php":
            return httpx.Response(
                200,
                text='<form action="/archiver.php"><input name="token" value="form-token">'
                '<input type="submit" name="download" value="Download"></form>',
            )
        if request.method == "POST":
            return httpx.Response(
                200, text='<a href="/archive/file.zip">Download archive</a>'
            )
        if request.url.path == "/archive/file.zip":
            return httpx.Response(
                200,
                content=archive_bytes,
                headers={
                    "content-type": "application/zip",
                    "content-disposition": 'attachment; filename="gallery.zip"',
                },
            )
        raise AssertionError(f"unexpected request: {request}")

    client = ArchiveClient(
        make_settings(tmp_path), transport=httpx.MockTransport(handler)
    )
    progress = AsyncMock()
    result = asyncio.run(client.download("https://e-hentai.org/g/12/abcdef/", progress))

    assert result.name == "gallery.zip"
    assert result.read_bytes() == archive_bytes
    assert not list(tmp_path.glob("*.part"))
    progress_messages = [call.args[0] for call in progress.await_args_list]
    assert any("100%" in message for message in progress_messages)
    assert any("validating archive" in message for message in progress_messages)
    assert calls == [
        ("GET", "/archiver.php"),
        ("POST", "/archiver.php"),
        ("GET", "/archive/file.zip"),
    ]


def test_external_redirect_is_blocked(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            302, headers={"location": "https://attacker.example/archive.zip"}
        )

    client = ArchiveClient(
        make_settings(tmp_path), transport=httpx.MockTransport(handler)
    )

    async def request():
        async with client._client() as http_client:
            await client._request(
                http_client, "GET", "https://e-hentai.org/archiver.php"
            )

    with pytest.raises(RuntimeError, match="allow-list"):
        asyncio.run(request())


def test_transient_get_failures_are_retried(monkeypatch, tmp_path):
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            return httpx.Response(503)
        return httpx.Response(200, text="ready")

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    client = ArchiveClient(
        make_settings(tmp_path), transport=httpx.MockTransport(handler)
    )

    async def request():
        async with client._client() as http_client:
            response = await client._request(
                http_client, "GET", "https://e-hentai.org/archiver.php"
            )
            await response.aclose()

    asyncio.run(request())
    assert attempts == 3


def test_invalid_archive_is_removed(tmp_path):
    settings = make_settings(tmp_path)
    client = ArchiveClient(settings)
    response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://e-hentai.org/file"),
        content=b"<html>not an archive</html>",
        headers={"content-type": "application/octet-stream"},
    )

    with pytest.raises(RuntimeError, match="not a recognized"):
        asyncio.run(client._save_response(response, "12", AsyncMock()))
    assert list(tmp_path.iterdir()) == []


def test_stream_that_exceeds_limit_removes_partial_file(tmp_path):
    class ChunkedStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"PK\x03\x04"
            yield b"too-large"

    settings = make_settings(
        tmp_path,
        max_archive_bytes=5,
        max_total_bytes=10,
    )
    client = ArchiveClient(settings)
    response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://e-hentai.org/file"),
        stream=ChunkedStream(),
        headers={"content-type": "application/octet-stream"},
    )

    with pytest.raises(RuntimeError, match="partial file was removed"):
        asyncio.run(client._save_response(response, "12", AsyncMock()))
    assert list(tmp_path.iterdir()) == []


def test_interrupted_stream_removes_partial_file(tmp_path):
    class FailingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"PK\x03\x04"
            raise httpx.ReadError("connection lost")

    client = ArchiveClient(make_settings(tmp_path))
    response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://e-hentai.org/file"),
        stream=FailingStream(),
        headers={"content-type": "application/octet-stream"},
    )

    with pytest.raises(httpx.ReadError):
        asyncio.run(client._save_response(response, "12", AsyncMock()))
    assert list(tmp_path.iterdir()) == []


def test_completed_archive_never_overwrites_existing_file(tmp_path):
    existing = tmp_path / "gallery.zip"
    existing.write_bytes(b"original")
    client = ArchiveClient(make_settings(tmp_path))
    response = httpx.Response(
        200,
        request=httpx.Request("GET", "https://e-hentai.org/file"),
        content=b"PK\x03\x04new",
        headers={
            "content-type": "application/zip",
            "content-disposition": 'attachment; filename="gallery.zip"',
        },
    )

    destination = asyncio.run(client._save_response(response, "12", AsyncMock()))
    assert existing.read_bytes() == b"original"
    assert destination != existing
    assert destination.read_bytes() == b"PK\x03\x04new"


def test_total_storage_quota_is_enforced(tmp_path):
    (tmp_path / "existing.zip").write_bytes(b"x" * 20)
    settings = make_settings(
        tmp_path,
        max_archive_bytes=20,
        max_total_bytes=20,
    )
    client = ArchiveClient(settings)
    with pytest.raises(RuntimeError, match="quota"):
        client._storage_budget()


def test_web_login_cookie_collection_and_file_permissions(tmp_path):
    output = tmp_path / ".env"
    collector = CookieCollector(output, require_exhentai=True)
    collector.capture("ignored=x; ipb_member_id=123; ipb_pass_hash=hash; igneous=gate")

    cookies = parse_cookie_string(
        "ignored=x; ipb_member_id=123; ipb_pass_hash=hash; igneous=gate"
    )
    assert (
        cookie_header(cookies) == "ipb_member_id=123; ipb_pass_hash=hash; igneous=gate"
    )
    assert is_ready(cookies, require_exhentai=True)
    assert os.stat(output).st_mode & 0o777 == 0o600


def test_web_login_requires_igneous_for_exhentai():
    cookies = parse_cookie_string("ipb_member_id=123; ipb_pass_hash=hash")
    assert is_ready(cookies, require_exhentai=False)
    assert not is_ready(cookies, require_exhentai=True)


def test_worker_processes_a_queued_job(tmp_path):
    archive = tmp_path / "done.zip"
    archive.write_bytes(b"PK\x03\x04done")

    class FakeClient:
        async def download(self, url, progress):
            await progress("working")
            return archive

    async def scenario():
        service = BotService(make_settings(tmp_path), client=FakeClient())
        notice = AsyncMock()
        worker = asyncio.create_task(service._worker())
        await service.queue.put(
            ArchiveJob("https://e-hentai.org/g/12/abcdef/", notice, 123)
        )
        await service.queue.join()
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker
        return notice

    notice = asyncio.run(scenario())
    assert notice.edit_text.await_count == 2
    assert "Download completed successfully" in notice.edit_text.await_args.args[0]


def test_worker_reports_failed_download(tmp_path):
    class FailingClient:
        async def download(self, url, progress):
            await progress("requesting")
            raise RuntimeError("site rejected the archive request")

    async def scenario():
        service = BotService(make_settings(tmp_path), client=FailingClient())
        notice = AsyncMock()
        worker = asyncio.create_task(service._worker())
        await service.queue.put(
            ArchiveJob("https://e-hentai.org/g/12/abcdef/", notice, 123)
        )
        await service.queue.join()
        worker.cancel()
        with pytest.raises(asyncio.CancelledError):
            await worker
        return notice

    notice = asyncio.run(scenario())
    final_message = notice.edit_text.await_args.args[0]
    assert final_message.startswith("❌ Download failed")
    assert "site rejected" in final_message
