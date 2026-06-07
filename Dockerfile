FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FORWARDED_ALLOW_IPS=*

WORKDIR /app

RUN addgroup --system keyvault \
    && adduser --system --ingroup keyvault keyvault \
    && apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY docker-entrypoint.sh /usr/local/bin/keyvault-entrypoint

RUN mkdir -p /app/data /app/uploads \
    && chown -R keyvault:keyvault /app \
    && chmod +x /usr/local/bin/keyvault-entrypoint

EXPOSE 8080

ENTRYPOINT ["keyvault-entrypoint"]
CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port 8080 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-*}\""]
