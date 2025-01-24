# Use a lightweight base image with a package manager
FROM ubuntu:latest

# Update package list and install build-essential (includes g++)
RUN apt-get update && apt-get install -y g++ && apt-get clean

# Set the working directory inside the container
WORKDIR /app

# Copy the C++ source code into the container
COPY hello.cpp .

# Compile the C++ program
RUN g++ -o hello hello.cpp

# Specify the command to run the program
CMD ["./hello"]
