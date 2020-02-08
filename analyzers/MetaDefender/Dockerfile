# THIS FILE IS UPDATED BY `utils/dockerfile_builder.py`
# DO NOT EDIT IT DIRECTLY


# Guessing base image from source code shebang
FROM python:3-alpine

LABEL name="MetaDefenderCore_GetReport"
LABEL description="Get the latest MetaDefender Core report for hash."
LABEL author="Davide Arcuri and Andrea Garavaglia, LDO-CERT"

WORKDIR /worker

COPY . MetaDefenderCore_GetReport

# Project determined to be Python, installing deps
RUN pip install --no-cache-dir -r MetaDefenderCore_GetReport/requirements.txt

ENTRYPOINT MetaDefender/metadefender_lookup.py