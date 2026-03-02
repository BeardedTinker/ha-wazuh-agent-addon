ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-debian:bookworm
FROM ${BUILD_FROM}

ARG BUILD_ARCH
ARG BUILD_VERSION

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     curl ca-certificates gnupg jq systemd \
  && rm -rf /var/lib/apt/lists/*

# Install Wazuh repository
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /usr/share/keyrings/wazuh.gpg \
  && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" \
     > /etc/apt/sources.list.d/wazuh.list

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD [ "/run.sh" ]
