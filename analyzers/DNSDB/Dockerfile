FROM python:2

WORKDIR /worker
COPY . DNSDB
RUN pip install --no-cache-dir -r DNSDB/requirements.txt
ENTRYPOINT DNSDB/dnsdb.py
