## To test an Analyzer of Responder with docker: 
#
# Copy this file in the folder of an analyzer or a responder and name it Dockerfile
## edit it and Change variables
#
# - {workername} by the folder name of the analyzer or responder
# - {command} by the value of the `command` in a JSON file
# 
# Save and run: 
#
# docker build -t cortexneurons/{flavor_name}:devel  with {flavor_name} the name of the analyzer of responder in the JSON file
#
# 



FROM python:3
WORKDIR /worker
WORKDIR /worker
COPY . ClamAV
RUN test ! -e ClamAV/requirements.txt || pip install --no-cache-dir -rClamAV/requirements.txt
RUN apt update
RUN apt install -y clamav clamav-daemon build-essential
RUN service clamav-freshclam start
RUN service clamav-daemon start
ENTRYPOINT service clamav-freshclam start && service clamav-daemon start && ClamAV/pyclam_analyzer.py
