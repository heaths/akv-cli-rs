FROM mcr.microsoft.com/devcontainers/rust:1-1-bullseye
RUN apt-get update \
 && export DEBIAN_FRONTEND=noninteractive \
 && apt-get -y install --no-install-recommends \
      git \
      xsltproc \
 # Clean up
 && apt-get autoremove -y \
 && apt-get clean - \
 && rm -rf /var/lib/apt/lists/*
