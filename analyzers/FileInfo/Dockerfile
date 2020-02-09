### AUTOGEN ###
# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY

FROM ubuntu

RUN apk add --no-cache libmagic git

LABEL name="FileInfo"
LABEL description="Parse files in several formats such as OLE and OpenXML to detect VBA macros, extract their source code, generate useful information on PE, PDF files..."
LABEL author="TheHive-Project"

WORKDIR /worker

COPY . FileInfo

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r FileInfo/requirements.txt

ENTRYPOINT FileInfo/fileinfo_analyzer.py