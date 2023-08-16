FROM python:3.9

WORKDIR /worker
COPY . VirusTotal
RUN apt update
RUN apt install -y -q libimage-exiftool-perl       && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r VirusTotal/requirements.txt

ENTRYPOINT VirusTotal/virustotal.py