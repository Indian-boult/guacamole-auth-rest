# Use Ubuntu as the base image
FROM ubuntu:latest

# Update package lists and install necessary packages
RUN apt-get update && apt-get install -y \
    openjdk-8-jdk \
    maven \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the project files into the container
COPY . .

# Build the project
RUN mvn clean package

# Set the entry point to run the application
CMD ["java", "-jar", "target/guacamole-auth-rest-1.0.0-SNAPSHOT.jar"]
