FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN python -m pip install --no-cache-dir -U pip \
    && python -m pip install --no-cache-dir .

# This base image runs dnsRecon Python-native engine. Optional OSS adapters work
# automatically when their binaries are installed in a custom image or mounted in PATH.
ENTRYPOINT ["dnsRecon"]
