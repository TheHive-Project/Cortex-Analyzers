FROM python:3-slim
WORKDIR /worker
COPY . Crtsh
RUN test ! -e Crtsh/requirements.txt || pip install --no-cache-dir -r Crtsh/requirements.txt
ENTRYPOINT Crtsh/crtshquery.py
