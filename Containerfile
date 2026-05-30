FROM pulp/pulp-minimal:latest
LABEL org.opencontainers.image.source=https://github.com/otaviof/pulp_trustify
COPY . /src
RUN pip install /src && rm -rf /src
