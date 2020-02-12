FROM python:3-alpine

LABEL author="CERT-LaPoste" \
      description="Find look alike image via Google Cloud Vision API using the Web_Detection service " \
      license="AGPL-V3" \
      source="https://github.com/TheHive-Project/Cortex-Analyzers" \
      title="GoogleVisionAPI" \
      url="https://github.com/TheHive-Project/Cortex-Analyzers" \
      vendor="TheHive" \
      version="1.0.0"

WORKDIR /worker

COPY . GoogleVisionAPI
RUN pip install --no-cache-dir -r GoogleVisionAPI/requirements.txt

ENTRYPOINT GoogleVisionAPI/GoogleVisionAPI_WebDetection.py