FROM cortex-base-python3
ADD ./analyzers/FireHOLBlocklists /analyzer
WORKDIR /analyzer
RUN pip3 install --no-cache-dir -r requirements.txt
RUN git clone https://github.com/firehol/blocklist-ipsets/ blocklists
