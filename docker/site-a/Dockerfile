FROM alpine:3.19

RUN apk add --no-cache \
    strongswan \
    iputils \
    iproute2 \
    tcpdump \
    bash

COPY ipsec.conf    /etc/ipsec.conf
COPY ipsec.secrets /etc/ipsec.secrets
COPY entrypoint.sh /entrypoint.sh

RUN chmod 600 /etc/ipsec.secrets && \
    chmod +x /entrypoint.sh && \
    sed -i 's/\r//' /entrypoint.sh

ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
