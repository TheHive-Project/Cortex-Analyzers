FROM alpine:latest

ARG BUILD_DATE
ARG VCS_REF
ARG VERSION

LABEL org.label-schema.build-date=$BUILD_DATE \
          org.label-schema.name="Cortex-Analyzers Python3 base image" \
          org.label-schema.description="This is the base image for using analyzers with python3." \
          org.label-schema.url="https://thehive-project.org" \
          org.label-schema.vcs-ref=$VCS_REF \
          org.label-schema.vcs-url="e.g. https://github.com/TheHive-Project/Cortex-Analyzers" \
          org.label-schema.vendor="TheHive-Project" \
          org.label-schema.version=$VERSION \
          org.label-schema.schema-version="1.0"

RUN apk add --no-cache python3 py-pip git && pip install --upgrade --no-cache-dir pip cortexutils
