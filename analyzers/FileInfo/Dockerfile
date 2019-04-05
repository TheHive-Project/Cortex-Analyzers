FROM python:3

WORKDIR /worker
COPY . FileInfo
RUN apt update                                                  && \
    apt install -y -q libfuzzy-dev libimage-exiftool-perl       && \
    rm -rf /var/lib/apt/lists/*                                 && \
    pip install --no-cache-dir -r FileInfo/requirements.txt
ENTRYPOINT FileInfo/fileinfo_analyzer.py
