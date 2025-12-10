FROM python:3-slim

# Install curl for downloading machinetag.json
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /worker

# Copy requirements and install Python dependencies
COPY requirements.txt AILOnionLookup/
RUN test ! -e AILOnionLookup/requirements.txt || pip install --no-cache-dir -r AILOnionLookup/requirements.txt

# Download MISP dark-web taxonomy machinetag.json
RUN curl -L -o AILOnionLookup/machinetag.json \
    https://raw.githubusercontent.com/MISP/misp-taxonomies/main/dark-web/machinetag.json

# Copy the analyzer code
COPY . AILOnionLookup/

ENTRYPOINT ["python", "AILOnionLookup/OnionLookup.py"]