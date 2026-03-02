ARG BUILD_FROM
FROM ${BUILD_FROM}

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apk add --no-cache bash curl ca-certificates

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
