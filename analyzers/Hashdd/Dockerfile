FROM python:3-alpine

LABEL author="iosonogio" \
      license="AGPLv3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Hashdd" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Hashdd
RUN pip install --no-cache-dir -r Hashdd/requirements.txt

ENTRYPOINT Hashdd/Hashdd.py