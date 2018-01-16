FROM cortex-base-python3
ADD . /analyzer
WORKDIR /analyzer
#RUN apk add build-base
RUN apk add exiftool build-base python2-dev --update-cache --repository http://dl-3.alpinelinux.org/alpine/edge/main/ --allow-untrusted
RUN BUILD_LIB=1 pip install --no-cache-dir -r requirements.txt

