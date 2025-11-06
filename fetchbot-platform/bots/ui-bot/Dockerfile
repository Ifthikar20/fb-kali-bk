FROM python:3.11-slim

# Install dependencies and web scanning tools
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    perl \
    libnet-ssleay-perl \
    && rm -rf /var/lib/apt/lists/*

# Install Nikto from source
RUN git clone --depth 1 https://github.com/sullo/nikto /opt/nikto

# Install WhatWeb from source
RUN git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb

# Add tools to PATH
ENV PATH="/opt/nikto/program:/opt/whatweb:${PATH}"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8001

CMD ["python", "ui_bot.py"]
