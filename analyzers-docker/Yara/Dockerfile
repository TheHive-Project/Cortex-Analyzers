FROM cortex-base-python3
ADD ./analyzers/Yara /analyzer
WORKDIR /analyzer
RUN apk add build-base --update-cache --repository http://dl-3.alpinelinux.org/alpine/edge/base/ --allow-untrusted
RUN apk add python3-dev
RUN pip3 install --no-cache-dir -r requirements.txt

