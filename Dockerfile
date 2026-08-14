# syntax=docker/dockerfile:1
FROM ghcr.io/astral-sh/uv:0.12.3 AS uv
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    DOWNLOAD_DIR=/downloads

WORKDIR /app

COPY --from=uv /uv /uvx /bin/
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project

COPY bot.py .

RUN addgroup --system app && adduser --system --ingroup app --home /app app \
    && mkdir /downloads && chown app:app /downloads

USER app
VOLUME ["/downloads"]

CMD ["uv", "run", "--locked", "--no-sync", "python", "bot.py"]
