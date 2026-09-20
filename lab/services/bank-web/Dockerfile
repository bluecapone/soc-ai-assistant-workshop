FROM python:3.12-slim

# iputils-ping so the intentional command-injection endpoint (/run) has a real
# command to abuse, matching how a web shell would pivot.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

RUN mkdir -p /var/log/bank-web /uploads

EXPOSE 8080
# One worker keeps the log lines and the sqlite file deterministic for the
# workshop's cross-room scoreboard. Our own access log is written in-app, so
# gunicorn's is silenced.
CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:8080", \
     "--access-logfile", "/dev/null", "app:app"]
