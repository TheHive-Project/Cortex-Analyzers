FROM python:3-slim
WORKDIR /worker
COPY . Jupyter
RUN test ! -e Jupyter/requirements.txt || pip install --no-cache-dir -r Jupyter/requirements.txt

RUN apt update &&\
     apt install patch &&\
     patch $(python3 -c "from papermill import iorw; print(iorw.__file__)") Jupyter/papermill_iorw.patch 
ENTRYPOINT ["python", "Jupyter/jupyter.py"]
