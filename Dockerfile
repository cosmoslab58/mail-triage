FROM python:3.13-slim
LABEL org.opencontainers.image.source=https://github.com/cosmoslab58/mail-triage \
      org.opencontainers.image.description="An LLM decides which of your emails get to interrupt you" \
      org.opencontainers.image.licenses=MIT
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY triage.py actions.py secretary.py unsubscribe.py providers.py notifiers.py fold_folders.py ./
ENV TRIAGE_CONFIG=/config/config.yaml TRIAGE_DATA=/data PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
# Run unprivileged. /data is the only path it writes (triage.db and heartbeat);
# a fresh named volume copies this ownership. An existing volume made by an
# older, root image needs a one-time `chown -R 10001:10001` of its contents.
RUN useradd --uid 10001 --user-group --no-create-home --shell /usr/sbin/nologin triage \
    && mkdir -p /data && chown 10001:10001 /data
USER 10001:10001
HEALTHCHECK --interval=5m --timeout=10s CMD python -c "import os,time,sys; sys.exit(time.time()-os.path.getmtime('/data/heartbeat')>900)"
CMD ["python", "triage.py", "run"]
