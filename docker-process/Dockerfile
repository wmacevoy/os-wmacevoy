# Start with an official base image that has GCC
FROM gcc:14 AS builder

# Set the working directory
WORKDIR /app

# Copy source code into container
COPY hello.c .

# Compile the program
RUN gcc -O3 -g -o hello hello.c

# Use a small runtime image
FROM debian:stable-slim

WORKDIR /app

# Copy the compiled binary from the builder stage
COPY --from=builder /app/hello .

# Default command to run when the container starts
CMD ["./hello"]