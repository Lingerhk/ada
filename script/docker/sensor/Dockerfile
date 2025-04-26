# Note: This Dockerfile must run in windows


# Stage 1: Build the Go application
ARG IMAGE=golang:1.24.2-windowsservercore-ltsc2022
FROM ${IMAGE}

# Set the working directory inside the container
WORKDIR /app

# Copy the entire source code (including make.bat in cmd/)
COPY . .

WORKDIR /app/agent/sensor/cmd

RUN cmd /C make.bat