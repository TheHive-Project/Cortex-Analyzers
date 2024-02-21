FROM python:3.10-alpine
WORKDIR /worker
COPY . BinalyzeAIR/
RUN pip3 install --no-cache-dir -r BinalyzeAIR/requirements.txt
ENTRYPOINT ["python3", "BinalyzeAIR/binalyze.py"]