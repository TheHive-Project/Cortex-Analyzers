FROM python:3.11
WORKDIR /worker
COPY . Autofocus
RUN test ! -e Autofocus/requirements.txt || pip install --no-cache-dir -r Autofocus/requirements.txt
ENTRYPOINT Autofocus/analyzer.py
