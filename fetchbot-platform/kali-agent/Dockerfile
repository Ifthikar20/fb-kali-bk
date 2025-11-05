FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Update and install essential security tools
RUN apt-get update && apt-get install -y \
    # Network scanning
    nmap \
    masscan \
    dnsutils \
    netcat-traditional \
    # Web scanning
    nikto \
    dirb \
    whatweb \
    curl \
    wget \
    # Database testing
    sqlmap \
    # Python and development
    python3 \
    python3-pip \
    python3-venv \
    git \
    # Utilities
    vim \
    tmux \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python packages (Kali Linux requires --break-system-packages for pip in containers)
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy agent code
COPY kali_agent.py .

# Expose port for agent API
EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:9000/health || exit 1

# Run the agent
CMD ["python3", "kali_agent.py"]
