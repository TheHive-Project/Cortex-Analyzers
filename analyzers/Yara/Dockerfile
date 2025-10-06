FROM python:3-alpine
WORKDIR /worker

# Install build dependencies for compiling native extensions
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev 

COPY requirements.txt Yara/
RUN test ! -e Yara/requirements.txt || pip install --no-cache-dir -r Yara/requirements.txt
COPY . Yara/

ENTRYPOINT ["python", "Yara/yara_analyzer.py"]