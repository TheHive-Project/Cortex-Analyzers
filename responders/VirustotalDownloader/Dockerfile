FROM python:3-alpine

WORKDIR /worker

# install runtime dependencies.
RUN apk add --no-cache file-dev

COPY requirements.txt VirusTotalDownloader/

# Install Python dependencies from requirements.txt
RUN test ! -e VirusTotalDownloader/requirements.txt || pip install --no-cache-dir -r VirusTotalDownloader/requirements.txt

COPY . VirusTotalDownloader

ENTRYPOINT ["python", "VirusTotalDownloader/VirustotalDownloader.py"]
