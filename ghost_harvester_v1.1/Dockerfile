# Use a base image with Python and network tools
FROM python:3.9-slim-buster

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    aria2 \
    wireguard-tools \
    sudo \
    iproute2 \
    unzip \
    # Added for potential npyscreen dependencies or general utility
    build-essential \
    libncursesw5-dev \
    pkg-config \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install Python dependencies first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and .env.example
COPY src/ src/
COPY .env.example .
# Ensure the main_harvester.py is executable
# The CMD will call python3 src/main_harvester.py, so direct chmod +x is not strictly necessary
# for python execution but good practice if it were a script to be run directly.
# RUN chmod +x src/main_harvester.py

# Entrypoint to run the main application
CMD ["python3", "src/main_harvester.py"]
