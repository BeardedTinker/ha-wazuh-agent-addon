ARG BUILD_FROM
FROM ${BUILD_FROM}

ARG BUILD_ARCH
ARG BUILD_VERSION

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates curl gnupg jq \
  && rm -rf /var/lib/apt/lists/*

# Wazuh repo key + repo (non-interactive safe)
RUN curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg \
  && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" \
    > /etc/apt/sources.list.d/wazuh.list

# Install wazuh-agent in the image (NO apt on startup)
RUN apt-get update \
  && apt-get install -y --no-install-recommends wazuh-agent \
  && rm -rf /var/lib/apt/lists/*

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
