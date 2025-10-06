FROM python:3-alpine
WORKDIR /worker

# Install libmagic (development package provides libmagic.so symlink)
RUN apk add --no-cache file-dev

COPY requirements.txt Gmail/
RUN test ! -e Gmail/requirements.txt || pip install --no-cache-dir -r Gmail/requirements.txt
COPY . Gmail/

ENTRYPOINT ["python", "Gmail/Gmail.py"]