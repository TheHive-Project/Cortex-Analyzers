FROM python:3.8

WORKDIR /worker
COPY . FileInfo
RUN apt update
RUN apt install -y -q libboost-regex-dev                           \
    libboost-program-options-dev                                      \
    libboost-system-dev libboost-filesystem-dev libssl-dev            \
    build-essential cmake                                             \
    git 
RUN git clone https://github.com/JusticeRage/Manalyze.git       && \
    cd Manalyze                                                     && \
    cmake .                                                         && \
    make -j5                                                        && \
    cd bin/yara_rules                                               && \ 
    python2 update_clamav_signatures.py
RUN apt update                                                  && \
    apt install -y -q libfuzzy-dev libimage-exiftool-perl       && \
    rm -rf /var/lib/apt/lists/*                                 && \
    pip install --no-cache-dir -r FileInfo/requirements.txt
ENTRYPOINT FileInfo/fileinfo_analyzer.py
