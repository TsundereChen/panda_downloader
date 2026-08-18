import asyncio
import logging
import os
import sys
import threading
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
    GalleryPreview,
    SecretRedactingFormatter,
    Settings,
    archive_html_state,
    archive_link_from_html,
    archive_preparation_progress_message,
    download_progress_message,
    enable_function_call_logging,
    extract_gallery_url,
    filename_from_response,
    format_bytes,
    gallery_confirmation_caption,
    gallery_preview_from_html,
    normalize_cookie_header,
    parse_cookie_header,
    parse_gallery_url,
    safe_url_for_log,
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


def stub_gallery_preview(
    service: BotService, *, image: bytes | None = None
) -> GalleryPreview:
    preview = GalleryPreview(
        gallery_name="日本語のタイトル",
        english_name="English Gallery Title",
        language="Japanese",
        file_size="42.0 MiB",
        length="123 pages",
        image_url="https://ehgt.org/g/cover.jpg",
        image=image,
    )
    service.client.gallery_preview = AsyncMock(return_value=preview)
    return preview


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


def test_gallery_preview_parser_extracts_titles_details_and_cover():
    preview = gallery_preview_from_html(
        """
        <h1 id="gn">English Gallery Title</h1>
        <h1 id="gj">日本語のタイトル</h1>
        <div id="gd1"><div style="width:240px; height:320px; background:url(https://ehgt.org/g/cover.jpg)"></div></div>
        <div id="gdd"><table>
          <tr><td class="gdt1">Language:</td><td class="gdt2">Japanese <span>TR</span></td></tr>
          <tr><td class="gdt1">File Size:</td><td class="gdt2">42.0 MiB</td></tr>
          <tr><td class="gdt1">Length:</td><td class="gdt2">123 pages</td></tr>
        </table></div>
        """,
        "https://e-hentai.org/g/12/abcdef/",
    )

    assert preview.gallery_name == "日本語のタイトル"
    assert preview.english_name == "English Gallery Title"
    assert preview.language == "Japanese"
    assert preview.file_size == "42.0 MiB"
    assert preview.length == "123 pages"
    assert preview.image_url == "https://ehgt.org/g/cover.jpg"


def test_gallery_confirmation_caption_contains_requested_metadata_and_is_bounded():
    preview = GalleryPreview(
        gallery_name="日" * 500,
        english_name="English title",
        language="Japanese",
        file_size="42.0 MiB",
        length="123 pages",
        image_url=None,
    )

    caption = gallery_confirmation_caption(
        preview, "https://e-hentai.org/g/12/abcdef/", "original files"
    )

    assert "Gallery name:" in caption
    assert "English name: English title" in caption
    assert "Language: Japanese" in caption
    assert "File size: 42.0 MiB" in caption
    assert "Length: 123 pages" in caption
    assert len(caption) <= 1024


def test_cookie_header_parser_keeps_only_required_site_cookies():
    assert parse_cookie_header(
        "unrelated=one; ipb_member_id=123; ipb_pass_hash=two=three; igneous=gate"
    ) == {"ipb_member_id": "123", "ipb_pass_hash": "two=three", "igneous": "gate"}


def test_cookie_header_normalizes_podman_literal_quotes():
    header = "'ipb_member_id=123; ipb_pass_hash=hash; igneous=gate'"

    assert normalize_cookie_header(header) == header[1:-1]
    assert parse_cookie_header(header) == {
        "ipb_member_id": "123",
        "ipb_pass_hash": "hash",
        "igneous": "gate",
    }


def test_cookie_header_rejects_unmatched_quotes():
    with pytest.raises(RuntimeError, match="unmatched"):
        parse_cookie_header("'ipb_member_id=123; ipb_pass_hash=hash")


def test_log_formatter_redacts_bot_token_and_cookie_values():
    formatter = SecretRedactingFormatter(
        "%(levelname)s %(message)s",
        ("123456:telegram-secret", "cookie-secret"),
    )
    record = logging.LogRecord(
        name="httpx",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="POST https://api.telegram.org/bot%s/getMe cookie=%s",
        args=("123456:telegram-secret", "cookie-secret"),
        exc_info=None,
    )

    rendered = formatter.format(record)

    assert "123456:telegram-secret" not in rendered
    assert "cookie-secret" not in rendered
    assert rendered.count("<redacted>") == 2


def test_logging_helpers_do_not_expose_url_queries_or_html_content():
    formatter = SecretRedactingFormatter("%(message)s", ())
    record = logging.LogRecord(
        name="bot",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg="GET https://e-hentai.org/archiver.php?gid=12&token=secret-token",
        args=(),
        exc_info=None,
    )

    assert formatter.format(record) == (
        "GET https://e-hentai.org/archiver.php?<redacted-query>"
    )
    assert safe_url_for_log(
        "https://user:password@e-hentai.org/archiver.php?token=secret#fragment"
    ) == "https://e-hentai.org/archiver.php"

    state = archive_html_state(
        '<form><input name="dltype"><input name="dlcheck" value="secret-token">'
        '</form><div id="continue"><a href="?token=secret-token">Next</a></div>'
    )
    assert "forms=1" in state
    assert "dltype_field=True" in state
    assert "dlcheck_field=True" in state
    assert "continue_link=True" in state
    assert "secret-token" not in state


def test_function_call_logging_records_names_without_values(caplog, monkeypatch):
    previous_profile = sys.getprofile()
    previous_thread_profile = threading.getprofile()
    monkeypatch.setenv("FUNCTION_TRACE_LOGGING", "true")
    caplog.set_level(logging.INFO, logger="bot")

    try:
        enable_function_call_logging()
        assert format_bytes(1024) == "1.0 KiB"
    finally:
        sys.setprofile(previous_profile)
        threading.setprofile(previous_thread_profile)

    assert "function event=call name=format_bytes" in caplog.text
    assert "function event=return name=format_bytes" in caplog.text
    assert "1024" not in caplog.text


def test_completed_link_is_resolved_and_external_link_is_rejected(caplog):
    caplog.set_level(logging.INFO, logger="bot")
    assert (
        archive_link_from_html(
            '<a href="/archive/file.zip">Download archive</a>', "https://e-hentai.org/a"
        )
        == "https://e-hentai.org/archive/file.zip"
    )
    assert (
        archive_link_from_html(
            '<div id="continue"><a href="https://attacker.example/file.zip">'
            "Download archive</a></div>",
            "https://e-hentai.org/a",
        )
        is None
    )
    assert "link_candidate_rejected" in caplog.text
    assert "host=attacker.example" in caplog.text
    assert "file.zip" in caplog.text


def test_official_download_link_replaces_autostart_with_start():
    assert archive_link_from_html(
        '<div id="db"><p><a href="/archive/12?token=abc&amp;autostart=1">'
        "Start download</a></p></div>",
        "https://e-hentai.org/download-page",
    ) == "https://e-hentai.org/archive/12?token=abc&start=1"


def test_official_hath_archive_subdomain_is_trusted_by_default():
    assert archive_link_from_html(
        '<div id="db"><p><a '
        'href="https://archive-node.hath.network/archive/token?autostart=1">'
        "Start download</a></p></div>",
        "https://e-hentai.org/archiver.php",
    ) == "https://archive-node.hath.network/archive/token?start=1"


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
    monkeypatch.setenv("EH_COOKIE", "ipb_member_id=1; ipb_pass_hash=hash")
    monkeypatch.setenv("ARCHIVE_DOWNLOAD_HOSTS", "https://bad.example")
    with pytest.raises(RuntimeError, match="hostnames"):
        Settings.from_env()


def test_settings_require_complete_site_cookie(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("ALLOWED_TELEGRAM_USER_IDS", "123")
    monkeypatch.setenv("EH_COOKIE", "ipb_pass_hash=hash; igneous=gate")

    with pytest.raises(RuntimeError, match="ipb_member_id"):
        Settings.from_env()


def test_settings_normalize_podman_cookie_quotes(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "token")
    monkeypatch.setenv("ALLOWED_TELEGRAM_USER_IDS", "123")
    monkeypatch.setenv(
        "EH_COOKIE", "'ipb_member_id=1; ipb_pass_hash=hash; igneous=gate'"
    )

    settings = Settings.from_env()

    assert settings.cookie_header == (
        "ipb_member_id=1; ipb_pass_hash=hash; igneous=gate"
    )


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
    stub_gallery_preview(service)
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


def test_gallery_handler_sends_cover_photo_with_metadata(tmp_path):
    service = BotService(make_settings(tmp_path))
    stub_gallery_preview(service, image=b"preview-image")
    update = fake_update(123)
    update.effective_message.text = "https://e-hentai.org/g/12/abcdef/"

    asyncio.run(service.gallery_message(update, None))

    photo_call = update.effective_message.reply_photo.await_args
    assert "Gallery name: 日本語のタイトル" in photo_call.kwargs["caption"]
    assert "English name: English Gallery Title" in photo_call.kwargs["caption"]
    assert "Language: Japanese" in photo_call.kwargs["caption"]
    assert "File size: 42.0 MiB" in photo_call.kwargs["caption"]
    assert "Length: 123 pages" in photo_call.kwargs["caption"]
    update.effective_message.reply_text.assert_not_awaited()


def test_confirmation_queues_download(tmp_path):
    service = BotService(make_settings(tmp_path))
    stub_gallery_preview(service)
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
    stub_gallery_preview(service)
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
    stub_gallery_preview(service)
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
        "⬇️ Downloading gallery.zip — stage 2/2\n"
        "50% — 512 B / 1.0 KiB"
    )
    assert "Received 512 B" in download_progress_message("gallery.zip", 512, None)


def test_archive_preparation_progress_formatting():
    assert archive_preparation_progress_message(75, 6, 5) == (
        "⏳ Preparing archive — stage 1/2\n"
        "Elapsed: 1m 15s • status check #6\n"
        "Next update in 5s"
    )


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


def test_archive_preparation_reports_every_status_check(monkeypatch, tmp_path):
    archive_posts = 0
    archive_bytes = b"PK\x03\x04archive"

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal archive_posts
        if request.method == "GET" and request.url.path == "/archiver.php":
            return httpx.Response(
                200,
                text=(
                    '<form action="/archiver.php">'
                    '<input name="token" value="form-token">'
                    '<input type="submit" name="download" value="Download">'
                    "</form>"
                ),
            )
        if request.method == "POST":
            archive_posts += 1
            if archive_posts < 3:
                return httpx.Response(200, text="Archive is being generated")
            return httpx.Response(
                200, text='<a href="/archive/file.zip">Download archive</a>'
            )
        if request.url.path == "/archive/file.zip":
            return httpx.Response(
                200,
                content=archive_bytes,
                headers={
                    "content-type": "application/zip",
                    "content-length": str(len(archive_bytes)),
                },
            )
        raise AssertionError(f"unexpected request: {request}")

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    client = ArchiveClient(
        make_settings(tmp_path), transport=httpx.MockTransport(handler)
    )
    progress = AsyncMock()

    asyncio.run(client.download("https://e-hentai.org/g/12/abcdef/", progress))

    messages = [call.args[0] for call in progress.await_args_list]
    preparation_messages = [
        message for message in messages if "Preparing archive" in message
    ]
    assert len(preparation_messages) == 2
    assert "status check #1" in preparation_messages[0]
    assert "status check #2" in preparation_messages[1]
    assert any("stage 2/2" in message for message in messages)


def test_archive_client_follows_jhentai_official_flow(
    caplog, monkeypatch, tmp_path
):
    calls = []
    archive_posts = 0
    archive_bytes = b"PK\x03\x04archive"

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal archive_posts
        calls.append((request.method, request.url.path, request.url.query))
        if request.method == "GET" and request.url.path == "/archiver.php":
            return httpx.Response(200, text='<form action="/archiver.php"></form>')
        if request.method == "POST" and request.url.path == "/archiver.php":
            archive_posts += 1
            assert request.headers["content-type"].startswith("multipart/form-data;")
            assert b'name="dltype"' in request.content
            assert b"org" in request.content
            assert b'name="dlcheck"' in request.content
            assert b"Download Original Archive" in request.content
            if archive_posts == 1:
                return httpx.Response(200, text="Archive is being generated")
            return httpx.Response(
                200,
                text='<div id="continue"><a href="/download-page">Continue</a></div>',
            )
        if request.url.path == "/download-page":
            return httpx.Response(
                200,
                text=(
                    '<div id="db"><p><a '
                    'href="/archive/12?token=abc&amp;autostart=1">Download</a></p></div>'
                ),
            )
        if request.url.path == "/archive/12":
            assert request.url.params.get("token") == "abc"
            assert request.url.params.get("start") == "1"
            assert "autostart" not in request.url.params
            return httpx.Response(
                200,
                content=archive_bytes,
                headers={"content-type": "application/zip"},
            )
        raise AssertionError(f"unexpected request: {request}")

    async def no_sleep(_delay):
        return None

    monkeypatch.setattr(asyncio, "sleep", no_sleep)
    caplog.set_level(logging.INFO, logger="bot")
    client = ArchiveClient(
        make_settings(tmp_path), transport=httpx.MockTransport(handler)
    )

    result = asyncio.run(
        client.download("https://e-hentai.org/g/12/abcdef/", AsyncMock())
    )

    assert result.read_bytes() == archive_bytes
    assert [call[:2] for call in calls] == [
        ("GET", "/archiver.php"),
        ("POST", "/archiver.php"),
        ("POST", "/archiver.php"),
        ("GET", "/download-page"),
        ("GET", "/archive/12"),
    ]
    log_output = caplog.text
    assert "archive step=initial_archiver_html_read" in log_output
    assert "archive step=preparation_poll_start check=1" in log_output
    assert "archive step=next_link_found" in log_output
    assert "archive step=stage_2_entered" in log_output
    assert "archive step=archive_validation_passed" in log_output
    assert "token=abc" not in log_output


def test_exhentai_download_requires_igneous_before_network_access(tmp_path):
    client = ArchiveClient(
        make_settings(
            tmp_path, cookie_header="ipb_member_id=1; ipb_pass_hash=hash"
        )
    )

    with pytest.raises(RuntimeError, match="igneous"):
        asyncio.run(
            client.download("https://exhentai.org/g/12/abcdef/", AsyncMock())
        )


def test_login_form_is_reported_as_expired_session_without_submission(tmp_path):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        return httpx.Response(
            200,
            text=(
                '<form action="https://forums.e-hentai.org/index.php?act=Login&amp;CODE=01">'
                '<input name="UserName"><input name="PassWord" type="password">'
                "</form>"
            ),
        )

    client = ArchiveClient(
        make_settings(tmp_path), transport=httpx.MockTransport(handler)
    )

    with pytest.raises(RuntimeError, match="not logged in or has expired"):
        asyncio.run(
            client.download("https://e-hentai.org/g/12/abcdef/", AsyncMock())
        )

    assert len(calls) == 1
    assert calls[0][0] == "GET"


def test_login_endpoint_403_is_reported_as_expired_session(tmp_path):
    response = httpx.Response(
        403,
        request=httpx.Request(
            "POST", "https://forums.e-hentai.org/index.php?act=Login&CODE=01"
        ),
    )

    with pytest.raises(RuntimeError, match="not logged in or has expired"):
        ArchiveClient(make_settings(tmp_path))._raise_for_site_error(response, "")


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
