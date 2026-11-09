FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MLKEM_HOST=0.0.0.0 \
    PORT=8000

WORKDIR /app

COPY . /app

RUN useradd --create-home --home-dir /home/appuser appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE ${PORT}

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import os, urllib.request; port = os.environ.get('PORT', '8000'); urllib.request.urlopen(f'http://127.0.0.1:{port}/healthz', timeout=5).read()" || exit 1

CMD ["python", "-m", "mlkem"]
