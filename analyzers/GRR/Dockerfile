# Builder stage
FROM python:3-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN test ! -e requirements.txt || pip install --user --no-cache-dir -r requirements.txt
# grr-api-client pins protobuf<4 and Werkzeug<3; overriding to pick up CVE fixes
RUN pip install --user --no-cache-dir --upgrade "protobuf>=5.29.6" "Werkzeug>=3.1.6"

# Runtime stage
FROM python:3-slim
WORKDIR /worker
COPY --from=builder /root/.local /root/.local
COPY . GRR/
ENV PATH=/root/.local/bin:$PATH
# grr_response_proto's stubs need the pure-Python protobuf implementation
ENV PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python
ENTRYPOINT ["python", "GRR/grrclient.py"]
