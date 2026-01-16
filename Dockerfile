FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy controller code
COPY controller/ .

# Run as non-root user
RUN useradd -m -u 1000 controller
USER controller

# Default command
CMD ["kopf", "run", "main.py", "--verbose"]
