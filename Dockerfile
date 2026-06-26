FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=5173 \
    AWG_DATA_DIR=/data

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client sshpass ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt gunicorn

COPY app.py ./
COPY templates ./templates

RUN useradd -r -u 10001 -g users -d /app -s /usr/sbin/nologin awgweb \
    && mkdir -p /data \
    && chown -R awgweb:users /app /data

USER awgweb
EXPOSE 5173

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5173/', timeout=3).read(1)" || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5173", "--workers", "1", "--timeout", "120", "app:app"]
