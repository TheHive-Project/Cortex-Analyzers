FROM python:3-alpine
WORKDIR /worker
# Install required tools
RUN apk add --no-cache \
    curl \
    jq \
    unzip \
    bash && \
    rm -rf /var/cache/apk/*

COPY requirements.txt Capa/
RUN test ! -e Capa/requirements.txt || pip install --no-cache-dir -r Capa/requirements.txt

# Add a script to fetch the latest capa release and extract it
COPY fetch_capa.sh /worker/fetch_capa.sh
RUN chmod +x /worker/fetch_capa.sh && /worker/fetch_capa.sh

COPY . Capa/

ENTRYPOINT ["python", "Capa/CapaAnalyze.py"]