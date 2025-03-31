FROM python:3-alpine

WORKDIR /worker

# install runtime dependencies.
RUN apk add --no-cache file-dev

COPY requirements.txt VirustotalDownloader/

# Install Python dependencies from requirements.txt
RUN test ! -e VirustotalDownloader/requirements.txt || pip install --no-cache-dir -r VirustotalDownloader/requirements.txt

COPY . VirustotalDownloader

ENTRYPOINT ["python", "VirustotalDownloader/VirustotalDownloader.py"]
