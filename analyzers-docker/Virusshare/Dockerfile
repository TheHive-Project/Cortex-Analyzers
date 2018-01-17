FROM cortex-base-python3
ADD ./analyzers/Virusshare /analyzer
WORKDIR /analyzer
RUN pip3 install --no-cache-dir -r requirements.txt
# Todo: RUN sh getHashes.sh virusshare
