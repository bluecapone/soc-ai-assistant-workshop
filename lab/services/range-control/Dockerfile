FROM python:3.12-slim

# curl and bash are the attack scripts' only dependencies.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl bash \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py breadcrumbs.py network.py .
COPY scripts/ ./scripts/
# Strip any CR bytes a Windows checkout (core.autocrlf) may have baked into the
# scripts. bash reads `set -euo pipefail\r` as an invalid option and the attack
# never fires; .gitattributes prevents this on fresh clones, this rescues copies
# already cloned with CRLF on the next rebuild.
RUN sed -i 's/\r$//' ./scripts/*.sh && chmod +x ./scripts/*.sh

EXPOSE 8000
CMD ["gunicorn", "--workers", "2", "--timeout", "90", "--bind", "0.0.0.0:8000", "app:app"]
