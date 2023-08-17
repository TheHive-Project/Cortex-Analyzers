# syntax=docker/dockerfile:1.3-labs
FROM python:3.9
WORKDIR /worker
COPY . Jupyter_Analyzer
RUN test ! -e Jupyter_Analyzer/requirements.txt || pip install --no-cache-dir -r Jupyter_Analyzer/requirements.txt
COPY ./patches /patches
RUN pip install papermill
RUN apt update
RUN apt install patch
RUN patch $(python3 -c "from papermill import iorw; print(iorw.__file__)") /patches/papermill_iorw.patch 
ENTRYPOINT Jupyter_Analyzer/jupyter.py


