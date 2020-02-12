FROM python:3-alpine

LABEL author="Michael Stensrud, Nordic Financial CERT" \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="MnemonicPDNS" \
      url="https://passivedns.mnemonic.no/search" \
      vendor="TheHive" \
      version="3.0.0"

WORKDIR /worker

COPY . MnemonicPDNS
RUN pip install --no-cache-dir -r MnemonicPDNS/requirements.txt

ENTRYPOINT MnemonicPDNS/pdns.py