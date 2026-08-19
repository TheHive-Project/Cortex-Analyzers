FROM python:3.11-slim-bookworm

WORKDIR /worker
RUN apt update
RUN apt update                                                     && \
    apt install -y -q libboost-regex-dev                              \
    libboost-program-options-dev                                      \
    libboost-system-dev libboost-filesystem-dev libssl-dev            \
    build-essential cmake unzip curl                                  \
    git                                                               \
    libfuzzy-dev libimage-exiftool-perl libmagic1                  && \
    rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/JusticeRage/Manalyze.git           && \
    cd Manalyze                                                     && \
    cmake .                                                         && \
    make -j5                                                        && \
    cd bin/yara_rules                                               && \
    pip3 install requests                                           && \
    python3 update_clamav_signatures.py
RUN curl -SL https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip  --output floss.zip && \
    unzip floss.zip -d /usr/bin
COPY . FileInfo
RUN pip install --no-cache-dir "setuptools<81" wheel cffi pycparser  && \
    pip install --no-cache-dir --no-build-isolation -r FileInfo/requirements.txt && \
    pip install --no-cache-dir --upgrade "setuptools>=83" "pip>=26.1.2"

ENTRYPOINT ["python","FileInfo/fileinfo_analyzer.py"]
