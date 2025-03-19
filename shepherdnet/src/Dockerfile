# Use the official Python image as the base
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /src

# Copy the requirements file into the container
COPY requirements.txt /src/

# Install ansible
RUN apt-get update && apt-get install -y ansible python3-paramiko

# Install any dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application files into the container
COPY . /src/

# Expose the port the Flask app will run on
EXPOSE 5000

# Command to run the Flask app
CMD ["flask", "run", "--host=0.0.0.0"]