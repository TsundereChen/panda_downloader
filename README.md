# Panda Downloader

A private Telegram bot that downloads E-Hentai/ExHentai gallery archives to a local folder. Requires a logged-in site session and only responds to allow-listed users in private chats.

## Setup

1. Create a bot with [@BotFather](https://t.me/BotFather) and copy the token.
2. Install [uv](https://docs.astral.sh/uv/) and sync dependencies:

   ```sh
   uv sync
   ```

3. Configure environment:

   ```sh
   cp .env.example .env
   chmod 600 .env
   ```

   Set `TELEGRAM_BOT_TOKEN` and `ALLOWED_TELEGRAM_USER_IDS` (comma-separated numeric IDs) in `.env`.

4. Get the site session cookie via the interactive WebView helper:

   ```sh
   uv run --extra login panda_web_login.py --write-env .env
   ```

   Alternatively, sign in via your browser and paste the `Cookie` header into `EH_COOKIE` manually. Cookies expire; rerun the helper when the bot reports an expired session.

5. Start the bot:

   ```sh
   uv run bot.py
   ```

## Docker

```sh
docker compose up --build -d
```

Compose loads `.env`, stores archives in the Docker-managed `downloads` volume, and runs a hardened container (read-only fs, dropped capabilities, no-new-privileges). The named volume preserves the unprivileged container user's write access.

To run without Compose:

```sh
docker build -t panda_downloader .
docker run -d --name panda_downloader --env-file .env \
  -e DOWNLOAD_DIR=/downloads -v panda_downloader-downloads:/downloads \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL --security-opt no-new-privileges --init \
  --restart unless-stopped panda_downloader
```

## Usage

Send a gallery URL in a private chat with the bot:

```
https://e-hentai.org/g/123456/abcdef1234/
```

The bot shows gallery metadata and asks for confirmation. On approval, it downloads the archive to `DOWNLOAD_DIR`. Unconfirmed prompts expire after ten minutes.

Set `ARCHIVE_TYPE=res` for resampled archives. Trusted download domains are `e-hentai.org`, `exhentai.org`, and `hath.network` (and subdomains); add others via `ARCHIVE_DOWNLOAD_HOSTS`.

## Configuration

Key environment variables:

| Variable | Description |
|---|---|
| `TELEGRAM_BOT_TOKEN` | Bot token from BotFather |
| `ALLOWED_TELEGRAM_USER_IDS` | Comma-separated numeric Telegram user IDs |
| `EH_COOKIE` | Site session cookie |
| `DOWNLOAD_DIR` | Archive storage path |
| `ARCHIVE_TYPE` | `org` (default) or `res` |
| `MAX_ARCHIVE_GIB` | Max single archive size |
| `MAX_TOTAL_DOWNLOAD_GIB` | Max total retained downloads |
| `MIN_FREE_DISK_GIB` | Min free disk headroom |
| `FUNCTION_TRACE_LOGGING` | Set `false` to disable call-level tracing |
