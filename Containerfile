FROM pulp/pulp-minimal:latest
COPY . /src
RUN pip install /src && rm -rf /src
