"""Interactive WebView login helper for E-Hentai and ExHentai.

This opens a normal, user-controlled desktop WebView. Complete any site
verification and login yourself; the helper only collects the resulting cookies
from the pages you visit and writes EH_COOKIE when the window closes.
"""

from __future__ import annotations

import argparse
import sys
import threading
from collections.abc import Iterable
from pathlib import Path

from dotenv import set_key

EH_HOME_URL = "https://e-hentai.org/"
EX_HOME_URL = "https://exhentai.org/"
COOKIE_NAMES = ("ipb_member_id", "ipb_pass_hash", "igneous")


def parse_cookie_string(cookie_string: str) -> dict[str, str]:
    """Extract only credentials that the bot needs from document.cookie."""
    result: dict[str, str] = {}
    for part in cookie_string.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name in COOKIE_NAMES and value:
            result[name] = value
    return result


def cookie_header(cookies: dict[str, str]) -> str:
    return "; ".join(f"{name}={cookies[name]}" for name in COOKIE_NAMES if cookies.get(name))


def is_ready(cookies: dict[str, str], require_exhentai: bool) -> bool:
    required = {"ipb_member_id", "ipb_pass_hash"}
    if require_exhentai:
        required.add("igneous")
    return required <= cookies.keys()


class CookieCollector:
    def __init__(self, output_path: Path, require_exhentai: bool) -> None:
        self.cookies: dict[str, str] = {}
        self.output_path = output_path
        self.require_exhentai = require_exhentai
        self.saved = False
        self._save_lock = threading.Lock()

    def capture(self, cookie_string: str) -> bool:
        """Called from the WebView; returns whether all required fields exist."""
        self.cookies.update(parse_cookie_string(cookie_string))
        if is_ready(self.cookies, require_exhentai=self.require_exhentai):
            self._save()
        # The browser script uses this narrower result to decide when to move
        # from the E-Hentai family to ExHentai.
        return is_ready(self.cookies, require_exhentai=False)

    def _save(self) -> None:
        with self._save_lock:
            if self.saved:
                return
            set_key(self.output_path, "EH_COOKIE", cookie_header(self.cookies), quote_mode="always")
            self.saved = True
            print(f"EH_COOKIE saved to {self.output_path}; you can close the window normally.")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Open a WebView and export an EH_COOKIE after you log in manually.")
    parser.add_argument("--write-env", type=Path, default=Path(".env"), metavar="PATH", help="target .env file (default: .env)")
    parser.add_argument(
        "--allow-eh-only",
        action="store_true",
        help="save after E-Hentai login even if you do not obtain ExHentai's igneous cookie",
    )
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        import webview
    except ImportError:
        print("Missing GUI dependency. Install it with: uv sync --extra login", file=sys.stderr)
        return 2

    require_exhentai = not args.allow_eh_only
    collector = CookieCollector(output_path=args.write_env, require_exhentai=require_exhentai)
    window = webview.create_window(
        "E-Hentai session setup",
        EH_HOME_URL,
        js_api=collector,
        width=1050,
        height=780,
    )

    def inject_cookie_capture() -> None:
        # The call is local (WebView → this process). It does not send cookies to
        # any third party. Reinstall after navigation, so visiting exhentai.org
        # captures igneous as well.
        window.run_js(
            """
            (() => {
              const exHome = "https://exhentai.org/";
              const send = () => {
                if (window.pywebview?.api?.capture) {
                  window.pywebview.api.capture(document.cookie).then((hasAccountCookies) => {
                    const onEhFamily = location.hostname === "e-hentai.org" || location.hostname.endsWith(".e-hentai.org");
                    if (hasAccountCookies && onEhFamily) {
                      // A WebView has no address bar. Once the user has
                      // completed the normal E-Hentai sign-in, continue to
                      // ExHentai automatically to acquire igneous.
                      location.assign(exHome);
                    }
                  }).catch(() => {});
                }
              };
              send();
              window.setInterval(send, 1500);
            })();
            """
        )

    window.events.loaded += inject_cookie_capture
    print("Complete the site verification and sign in in the displayed window.")
    print(f"The window starts on {EH_HOME_URL} and automatically opens {EX_HOME_URL} after E-Hentai sign-in.")
    print("When the terminal confirms EH_COOKIE was saved, close the window normally.")
    webview.start()

    if not collector.saved:
        missing = [
            name
            for name in COOKIE_NAMES
            if name not in collector.cookies and (require_exhentai or name != "igneous")
        ]
        print(f"No configuration was written. Missing required cookie(s): {', '.join(missing)}.", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
