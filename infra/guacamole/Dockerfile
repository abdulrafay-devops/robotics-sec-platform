# Guacamole jump host for the IDMZ. The stock image is Debian-based but ships
# without iproute2, so the startup route-override (route to OT via the router, for
# RDP brokering) silently failed. Add `ip` so the route installs.
FROM guacamole/guacamole:1.5.5
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
