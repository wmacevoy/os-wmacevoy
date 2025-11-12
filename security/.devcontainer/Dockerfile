
# Use a widely-available base to avoid platform/manifest issues on different hosts (eg. macOS/arm64).

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Arguments for the default non-root user.
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000

# Install common dev tools, sudo, and Python
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    sudo \
    openssh-client \
    build-essential \
    cmake \
    ninja-build \
    pkg-config \
    gdb \
    valgrind \
    libssh-dev \
    libssh2-1-dev \
    libssl-dev \
    zlib1g-dev \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Ensure Python packaging tools are up to date
RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel

# Create the 'vscode' user so the Remote - Containers extension can connect as that user.
# Make this idempotent and strict to avoid creating a malformed passwd entry.
RUN set -eux; \
    # Create group if it doesn't exist
    if ! getent group "${USERNAME}" >/dev/null; then \
        groupadd --gid "${USER_GID}" "${USERNAME}"; \
    fi; \
    # Create user if it doesn't exist, set a valid shell and create home
    if ! id -u "${USERNAME}" >/dev/null 2>&1; then \
        useradd --uid "${USER_UID}" --gid "${USER_GID}" -m -s /bin/bash "${USERNAME}"; \
    fi; \
    mkdir -p "/home/${USERNAME}"; \
    chown -R "${USER_UID}:${USER_GID}" "/home/${USERNAME}"; \
    # Allow sudo without password for the user (required by many dev container flows)
    echo "${USERNAME} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${USERNAME}; \
    chmod 0440 /etc/sudoers.d/${USERNAME}

ENV HOME=/home/${USERNAME}


