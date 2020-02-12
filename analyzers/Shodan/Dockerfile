FROM python:3-alpine

LABEL authors="ANSSI, Sebastien Larinier @Sebdraven" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Shodan" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers/Shodan" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . Shodan
RUN pip install --no-cache-dir -r Shodan/requirements.txt

ENTRYPOINT Shodan/shodan_analyzer.py