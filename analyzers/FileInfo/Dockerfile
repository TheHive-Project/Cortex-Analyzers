FROM python:3.9

WORKDIR /worker
COPY . FileInfo
RUN apt update
RUN apt install -y -q libboost-regex-dev                              \
    libboost-program-options-dev                                      \
    libboost-system-dev libboost-filesystem-dev libssl-dev            \
    build-essential cmake unzip curl                                  \
    git 
RUN git clone https://github.com/JusticeRage/Manalyze.git           && \
    cd Manalyze                                                     && \
    cmake .                                                         && \
    make -j5                                                        && \
    cd bin/yara_rules                                               && \ 
    pip3 install requests                                           && \ 
    python3 update_clamav_signatures.py                         
RUN apt update                                                  && \
    apt install -y -q libfuzzy-dev libimage-exiftool-perl       && \
    rm -rf /var/lib/apt/lists/*                                 && \
    pip install --no-cache-dir -r FileInfo/requirements.txt

RUN curl -SL https://github.com/mandiant/flare-floss/releases/download/v2.0.0/floss-v2.0.0-linux.zip  --output floss.zip && \
    unzip floss.zip -d /usr/bin
ENTRYPOINT FileInfo/fileinfo_analyzer.py