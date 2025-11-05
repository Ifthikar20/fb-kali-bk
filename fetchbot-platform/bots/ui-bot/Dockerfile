FROM python:3.11-slim

# Install web scanning tools
RUN apt-get update && apt-get install -y \
    nikto \
    whatweb \
    curl \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8001

CMD ["python", "ui_bot.py"]
