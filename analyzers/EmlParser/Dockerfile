FROM python:3-alpine

RUN apk add --no-cache g++ libmagic

LABEL author="ninsmith" \
      description="Parse Eml message" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="EmlParser" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.2.0"

WORKDIR /worker

COPY . EmlParser
RUN pip install --no-cache-dir -r EmlParser/requirements.txt

ENTRYPOINT EmlParser/parse.py