FROM --platform=${TARGETPLATFORM} node:18

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
     apt-transport-https \
     build-essential \
     ca-certificates \
     curl \
     cmake \
     git \
     git-crypt \
     gnupg \
     openssl \
     openssh-server \
     python3 \
     python3-pip \
     sudo \
     uuid-runtime

RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN usermod -a -G sudo node

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
     clang cmake chromium git libgtk-3-dev liblzma-dev libstdc++-12-dev ninja-build pkg-config 

USER node
RUN git config --global --add safe.directory /opt/flutter

WORKDIR /home/node

CMD bash
