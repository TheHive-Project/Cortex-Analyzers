FROM python:3-alpine
WORKDIR /worker

RUN apk update && apk add clamav clamav-daemon build-base

COPY requirements.txt ClamAV/
RUN test ! -e ClamAV/requirements.txt || pip install --no-cache-dir -r ClamAV/requirements.txt

RUN mkdir -p /run/clamav && chown clamav:clamav /run/clamav && chmod 750 /run/clamav
RUN mkdir -p /var/lib/clamav

COPY . ClamAV
RUN chmod +x ClamAV/entrypoint.sh

ENTRYPOINT ["/bin/sh", "ClamAV/entrypoint.sh"]
    