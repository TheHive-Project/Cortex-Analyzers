FROM python:3-slim
WORKDIR /worker
COPY . CheckPhish
RUN test ! -e CheckPhish/requirements.txt || pip install --no-cache-dir -r CheckPhish/requirements.txt
ENTRYPOINT CheckPhish/CheckPhish.py
