FROM python:3-alpine

WORKDIR /worker

# install runtime dependencies.
RUN apk add --no-cache perl-image-exiftool file-dev

COPY requirements.txt VirusTotal/

# Install Python dependencies from requirements.txt
RUN test ! -e VirusTotal/requirements.txt || pip install --no-cache-dir -r VirusTotal/requirements.txt

COPY . VirusTotal

ENTRYPOINT ["python", "VirusTotal/virustotal.py"]
