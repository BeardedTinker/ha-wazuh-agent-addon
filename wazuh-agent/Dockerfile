ARG BUILD_ARCH=amd64
# hadolint ignore=DL3006
FROM ghcr.io/home-assistant/${BUILD_ARCH}-base-debian:bookworm

ARG BUILD_ARCH
ARG BUILD_VERSION

# renovate: datasource=deb depName=wazuh-agent versioning=deb
ARG WAZUH_AGENT_VERSION=4.14.8-1

ENV DEBIAN_FRONTEND=noninteractive

# Upgrade inherited packages to apply available security fixes.
# hadolint ignore=DL3005,DL3008
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    jq \
  && rm -rf /var/lib/apt/lists/*

# This add-on does not use TempIO; remove the inherited binary and its attack surface.
RUN rm -f /usr/bin/tempio

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
