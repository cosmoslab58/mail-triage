FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY triage.py providers.py notifiers.py fold_folders.py ./
ENV TRIAGE_CONFIG=/config/config.yaml TRIAGE_DATA=/data PYTHONUNBUFFERED=1
HEALTHCHECK --interval=5m --timeout=10s CMD python -c "import os,time,sys; sys.exit(time.time()-os.path.getmtime('/data/heartbeat')>900)"
CMD ["python", "triage.py", "run"]
