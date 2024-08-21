# Use Debian 11 as the base image
FROM debian:11

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary tools: CMake, GCC, Make, and other build essentials
RUN apt-get update && apt-get install -y \
    cmake \
    gcc \
    g++ \
    make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /usr/src/copy_command

# Copy the entire project into the container
COPY . .

# Create a build directory
RUN mkdir -p build

# Run cmake, build the project, and then run tests
RUN cd build && cmake .. && cmake --build . && ctest --output-on-failure

# Default command (optional) to run when the container starts
CMD ["bash"]
