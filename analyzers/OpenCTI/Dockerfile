FROM python:3-alpine
WORKDIR /worker

# Install libmagic (development package provides libmagic.so symlink)
RUN apk add --no-cache file-dev

COPY requirements.txt OpenCTI/
RUN test ! -e OpenCTI/requirements.txt || pip install --no-cache-dir -r OpenCTI/requirements.txt
COPY . OpenCTI/

ENTRYPOINT ["python", "OpenCTI/opencti.py"]
