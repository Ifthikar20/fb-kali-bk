FROM python:3.11-slim

# Install network scanning tools
RUN apt-get update && apt-get install -y \
    nmap \
    masscan \
    dnsutils \
    netcat-traditional \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8002

CMD ["python", "network_bot.py"]
