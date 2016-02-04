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

# Arguments passed to the container will be passed to the mabo binary
ENTRYPOINT ["/mabo/mabo"]
