FROM python:3

WORKDIR /worker
COPY . DNSDB
RUN pip install --no-cache-dir -r DNSDB/requirements.txt
ENTRYPOINT DNSDB/dnsdb.py
