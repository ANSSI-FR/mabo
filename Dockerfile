# MaBo x Docker
FROM debian
MAINTAINER Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>

# Copy local files to the container
COPY . /mabo

# Install packages, build MaBo, then remove packages
RUN set -x && \
    PACKAGES="make oasis libbz2-ocaml-dev libzip-ocaml-dev libyojson-ocaml-dev gcc" &&\
    apt-get update && apt-get install -y $PACKAGES && \
    cd /mabo && make mabo && \
    apt-get remove -y $PACKAGES && \
    apt-get autoclean && apt-get --purge -y autoremove && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Copy the binary and libraries to the distroless image
FROM gcr.io/distroless/base
COPY --from=0 /lib/x86_64-linux-gnu/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1
COPY --from=0 /lib/x86_64-linux-gnu/libbz2.so.1.0 /lib/x86_64-linux-gnu/libbz2.so.1.0
COPY --from=0 /mabo/mabo .

# Arguments passed to the container will be passed to the mabo binary
ENTRYPOINT ["/mabo"]
