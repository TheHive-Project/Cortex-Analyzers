FROM python:3-alpine
WORKDIR /worker

ARG REQUIREMENTS=requirements.txt

# Install libmagic (development package provides libmagic.so symlink)
RUN apk add --no-cache file-dev

COPY requirements*.txt OpenCTI/
RUN test ! -e OpenCTI/${REQUIREMENTS} || pip install --no-cache-dir -r OpenCTI/${REQUIREMENTS}
RUN pip install --no-cache-dir --upgrade "setuptools>=83.0.0"
COPY . OpenCTI/

ENTRYPOINT ["python", "OpenCTI/opencti.py"]
