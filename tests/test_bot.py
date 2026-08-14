from bot import archive_link_from_html, filename_from_response, parse_cookie_header, parse_gallery_url
from eh_web_login import cookie_header, is_ready, parse_cookie_string
import httpx


def test_gallery_url_parser_accepts_both_hosts():
    assert parse_gallery_url("https://e-hentai.org/g/12/abcDEF/") == ("e-hentai.org", "12", "abcdef")
    assert parse_gallery_url("https://exhentai.org/g/9/123abc/?p=2") == ("exhentai.org", "9", "123abc")


def test_gallery_url_parser_rejects_other_sites():
    try:
        parse_gallery_url("https://example.com/g/12/abcdef/")
    except ValueError:
        pass
    else:
        raise AssertionError("untrusted URL accepted")


def test_cookie_header_parser():
    assert parse_cookie_header("a=one; b=two=three; ignored") == {"a": "one", "b": "two=three"}


def test_completed_link_is_resolved():
    assert archive_link_from_html('<a href="/archive/file.zip">Download archive</a>', "https://e-hentai.org/a") == "https://e-hentai.org/archive/file.zip"


def test_filename_content_disposition():
    request = httpx.Request("GET", "https://example.test/file")
    response = httpx.Response(200, request=request, headers={"content-disposition": 'attachment; filename="hello.zip"'})
    assert filename_from_response(response, "fallback.zip") == "hello.zip"


def test_web_login_cookie_collection():
    cookies = parse_cookie_string("ignored=x; ipb_member_id=123; ipb_pass_hash=hash; igneous=gate")
    assert cookie_header(cookies) == "ipb_member_id=123; ipb_pass_hash=hash; igneous=gate"
    assert is_ready(cookies, require_exhentai=True)


def test_web_login_requires_igneous_for_exhentai():
    cookies = parse_cookie_string("ipb_member_id=123; ipb_pass_hash=hash")
    assert is_ready(cookies, require_exhentai=False)
    assert not is_ready(cookies, require_exhentai=True)

