FROM python:3-alpine

LABEL author="CERT-BDF" \
      description="Parse Outlook MSG files and extract the main artifacts." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="MsgParser" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="3.0.0"

WORKDIR /worker

COPY . MsgParser
RUN pip install --no-cache-dir -r MsgParser/requirements.txt

ENTRYPOINT MsgParser/parse.py