FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client ca-certificates tzdata iputils-ping iproute2 arp-scan && rm -rf /var/lib/apt/lists/* && pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 --create-home appuser
COPY server.py schema.sql index.html setup.html portal.html scanner_agent.py backup.py restore_archive.py reset_admin_password.py ./
RUN mkdir -p /app/uploads && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["gunicorn", "--workers", "2", "--threads", "4", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "--access-logformat", "%(h)s %(l)s %(u)s %(t)s \"%(m)s %(U)s %(H)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"", "server:app"]
