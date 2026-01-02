# syntax=docker/dockerfile:1.3-labs
FROM python:3.12-slim-bookworm
WORKDIR /worker
COPY . Jupyter
RUN test ! -e Jupyter/requirements.txt || pip install --no-cache-dir -r Jupyter/requirements.txt
COPY ./patches /patches
RUN pip install papermill
RUN apt update
RUN apt install patch
RUN patch $(python3 -c "from papermill import iorw; print(iorw.__file__)") /patches/papermill_iorw.patch 
ENTRYPOINT ["python", "Jupyter/jupyter.py"]
