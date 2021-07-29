FROM python:3.7

WORKDIR /worker
COPY . FileInfo
RUN apt update
RUN apt install -y -q libboost-regex-dev                              \
    libboost-program-options-dev                                      \
    libboost-system-dev libboost-filesystem-dev libssl-dev            \
    build-essential cmake                                             \
    git 
#RUN git clone https://github.com/JusticeRage/Manalyze.git           && \
# Using fork with fix, waiting for the PR being validated on
# original repo
# PR: https://github.com/JusticeRage/Manalyze/pull/46
RUN git clone https://github.com/jeromeleonard/Manalyze.git           && \
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

RUN curl -SL https://github.com/fireeye/flare-floss/releases/download/v1.7.0/floss-v1.7.0-linux.zip  --output floss.zip && \
    unzip floss.zip -d /usr/bin
ENTRYPOINT FileInfo/fileinfo_analyzer.py
