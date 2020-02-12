FROM python:3-alpine

LABEL author="Manabu Niseki, @ninoseki" \
      license="MIT" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="SecurityTrails" \
      url="https://github.com/ninoseki/cortex-securitytrails" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . SecurityTrails
RUN pip install --no-cache-dir -r SecurityTrails/requirements.txt

ENTRYPOINT SecurityTrails/securitytrails_analyzer.py