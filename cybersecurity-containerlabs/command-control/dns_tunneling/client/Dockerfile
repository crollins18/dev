FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Install tshark and other dependencies
RUN apt-get update && apt-get install -y \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Set permissions for scripts
RUN chmod +x ./capture.sh

# Define entrypoint
# ENTRYPOINT ["./capture.sh"]