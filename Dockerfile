# Base Image
FROM python:3.10-slim-buster

# System Dependencies for MariaDB
RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install requirements
COPY ./requirements.txt /app/
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy source code
# Note: The project structure is was/ for code and config/ for settings
COPY ./was /app/was
COPY ./config /app/config

# Expose port
EXPOSE 8000

# Run Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "config.wsgi:application"]