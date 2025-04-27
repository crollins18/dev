# Use the official Ansible image based on Alpine
FROM alpine/ansible:latest

# Install frr ansible collection
RUN ansible-galaxy collection install frr.frr

# Set the working directory inside the container
WORKDIR /src

# Install system dependencies including build tools, Python headers, and required libraries
RUN apk add --no-cache \
    python3 python3-pip python3-dev python3-netaddr \
    build-base libffi-dev openssl-dev libssh-dev

# Create a Python virtual environment to avoid modifying the system-wide Python
RUN python3 -m venv /opt/venv

# Use the virtual environment's pip by updating PATH
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install build tools within the virtual environment
RUN pip install --upgrade pip setuptools wheel

# Copy the requirements file into the container
COPY requirements.txt .

# Install Python dependencies within the virtual environment
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files into the container
COPY . .

# Expose the port the Flask app will run on
EXPOSE 5000

# Command to run the Flask app
CMD ["flask", "run", "--host=0.0.0.0"]