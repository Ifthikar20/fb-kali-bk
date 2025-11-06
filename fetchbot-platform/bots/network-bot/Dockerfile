FROM python:3.11-slim

# Install build dependencies and network tools
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    netcat-traditional \
    curl \
    wget \
    git \
    gcc \
    make \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Install masscan from source
RUN git clone --depth 1 https://github.com/robertdavidgraham/masscan /tmp/masscan && \
    cd /tmp/masscan && \
    make -j$(nproc) && \
    make install && \
    cd / && \
    rm -rf /tmp/masscan

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8002

CMD ["python", "network_bot.py"]
