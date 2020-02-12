FROM python:3-alpine

LABEL author="CERT-BDF" \
      description="Find abuse contacts associated with domain names, URLs, IPs and email addresses." \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="Abuse_Finder" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="3.0.0"

WORKDIR /worker

COPY . Abuse_Finder

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r Abuse_Finder/requirements.txt

ENTRYPOINT Abuse_Finder/abusefinder.py