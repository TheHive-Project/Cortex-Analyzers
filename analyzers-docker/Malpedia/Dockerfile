FROM cortex-base-python3
ADD ./analyzers/Malpedia /analyzer
WORKDIR /analyzer
RUN apk add build-base --update-cache --repository http://dl-3.alpinelinux.org/alpine/edge/base/ --allow-untrusted && apk add python3-dev && pip3 install --no-cache-dir -r requirements.txt && apk del build-base python3-dev
CMD ./malpedia_analyzer.py
