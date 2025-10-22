# Use an official Ubuntu base image
FROM ubuntu:latest

# Set the maintainer label
LABEL maintainer="Warren <your-email@example.com>"

# Avoid prompts from apt during installation
ARG DEBIAN_FRONTEND=noninteractive

# Update and install necessary packages
RUN apt-get update && apt-get install -y \
    dosfstools \
    ntfs-3g \
    && rm -rf /var/lib/apt/lists/*

# Your commands for file creation and manipulation go here
# Example: Create a directory to work in
RUN mkdir /data

# Set the working directory
WORKDIR /data

# Command to keep the container running (modify as needed)
CMD ["tail", "-f", "/dev/null"]
