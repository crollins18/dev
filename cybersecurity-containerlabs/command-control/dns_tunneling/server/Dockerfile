FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files
COPY . .

# Set permissions for scripts
# RUN chmod +x ./server.sh

# Define entrypoint
# ENTRYPOINT ["./server.sh"]