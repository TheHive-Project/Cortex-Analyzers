FROM python:3-slim
WORKDIR /worker
COPY . Censys
RUN test ! -e Censys/requirements.txt || pip install --no-cache-dir -r Censys/requirements.txt
ENTRYPOINT Censys/censys_analyzer.py
