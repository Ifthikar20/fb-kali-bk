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

# Install SecLists wordlists (industry-standard collection)
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists && \
    rm -rf /usr/share/seclists/.git

# Create symlinks for common wordlist locations
RUN ln -s /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/wordlists/common.txt && \
    ln -s /usr/share/seclists/Discovery/Web-Content/big.txt /usr/share/wordlists/big.txt && \
    ln -s /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt /usr/share/wordlists/dirlist.txt && \
    ln -s /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt /usr/share/wordlists/passwords.txt && \
    ln -s /usr/share/seclists/Usernames/top-usernames-shortlist.txt /usr/share/wordlists/usernames.txt

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
