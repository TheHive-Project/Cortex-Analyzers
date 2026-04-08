# Builder stage
FROM python:3-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN test ! -e requirements.txt || pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3-slim
RUN apt-get update && apt-get install -y --no-install-recommends openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /worker
COPY --from=builder /root/.local /root/.local
COPY . LdapQuery/
ENV PATH=/root/.local/bin:$PATH
ENTRYPOINT ["python", "LdapQuery/ldapQuery.py"]
