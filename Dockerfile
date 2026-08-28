# Claude Tag identity federation private beta sample code.
# This is a reference implementation, not a production service.
# Review it against your own security requirements before any
# production use.

FROM python:3.13-slim

# The service runs as an unprivileged user.
RUN useradd --create-home --uid 10001 gateway

WORKDIR /app
COPY requirements.lock.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock.txt
COPY gateway ./gateway

USER gateway
EXPOSE 8000

# Mount or copy your config.yaml to this path. Downstream credentials
# are passed as environment variables, never baked into the image.
ENV GATEWAY_CONFIG=/app/config.yaml

CMD ["python", "-m", "uvicorn", "gateway.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
