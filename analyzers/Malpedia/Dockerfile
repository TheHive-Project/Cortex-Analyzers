FROM python:3-alpine
WORKDIR /worker

# Install build dependencies for compiling native extensions
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev 

COPY requirements.txt Malpedia/
RUN test ! -e Malpedia/requirements.txt || pip install --no-cache-dir -r Malpedia/requirements.txt
COPY . Malpedia/

ENTRYPOINT ["python", "Malpedia/malpedia_analyzer.py"]