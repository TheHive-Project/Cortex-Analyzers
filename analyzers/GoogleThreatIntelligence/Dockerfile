FROM python:3-alpine

WORKDIR /worker

# install runtime dependencies.
RUN apk add --no-cache perl-image-exiftool file-dev

COPY requirements.txt GoogleThreatIntelligence/

# Install Python dependencies from requirements.txt
RUN test ! -e GoogleThreatIntelligence/requirements.txt || pip install --no-cache-dir -r GoogleThreatIntelligence/requirements.txt

COPY . GoogleThreatIntelligence

ENTRYPOINT ["python", "GoogleThreatIntelligence/gti.py"]
