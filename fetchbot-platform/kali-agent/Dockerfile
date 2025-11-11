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
    # Modern fuzzers
    ffuf \
    gobuster \
    wfuzz \
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

# Download essential wordlists only (much faster than full SecLists)
RUN mkdir -p /usr/share/wordlists && \
    # Common web paths (4k entries, ~50KB)
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
        -o /usr/share/wordlists/common.txt && \
    # Bigger wordlist (20k entries, ~220KB)
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt \
        -o /usr/share/wordlists/big.txt && \
    # Top 1000 passwords (~9KB)
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt \
        -o /usr/share/wordlists/passwords.txt && \
    # Common usernames (~1KB)
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt \
        -o /usr/share/wordlists/usernames.txt && \
    # Medium directory list for thorough scans (2.3MB)
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt \
        -o /usr/share/wordlists/dirlist.txt

# Create working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python packages (Kali Linux requires --break-system-packages for pip in containers)
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy agent code
COPY dynamic_kali_agent.py .
COPY kali_agent.py .

# Expose port for agent API
EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:9000/health || exit 1

# Run the dynamic agent (new multi-agent system)
CMD ["python3", "dynamic_kali_agent.py"]
