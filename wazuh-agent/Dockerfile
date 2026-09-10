ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-debian:bookworm
# hadolint ignore=DL3006
FROM ${BUILD_FROM}

ARG BUILD_ARCH
ARG BUILD_VERSION

# renovate: datasource=deb depName=wazuh-agent versioning=deb
ARG WAZUH_AGENT_VERSION=4.14.7-1

ENV DEBIAN_FRONTEND=noninteractive

# Package versions are controlled by the versioned Home Assistant base image.
# hadolint ignore=DL3008
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    jq \
  && rm -rf /var/lib/apt/lists/*

# Wazuh repository key and stable 4.x repository.
RUN curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH -o /tmp/wazuh.key \
  && gpg --batch --yes --dearmor -o /usr/share/keyrings/wazuh.gpg /tmp/wazuh.key \
  && rm -f /tmp/wazuh.key \
  && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" \
    > /etc/apt/sources.list.d/wazuh.list

# Install an exact Wazuh Agent version at build time.
RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    "wazuh-agent=${WAZUH_AGENT_VERSION}" \
  && rm -rf /var/lib/apt/lists/*

COPY run.sh /run.sh
RUN chmod +x /run.sh

CMD ["/run.sh"]
