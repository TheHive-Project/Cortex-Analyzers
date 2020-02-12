FROM python:3-alpine

LABEL author="Guillaume Rousse" \
      description="Use Nessus Professional to scan hosts." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Nessus" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="2.0.0"

WORKDIR /worker

COPY . Nessus
RUN pip install --no-cache-dir -r Nessus/requirements.txt

ENTRYPOINT Nessus/nessus.py