FROM python:3.11-slim

# Métadonnées
LABEL maintainer="VulnHunter Pro"
LABEL description="Scanner de vulnérabilités web professionnel avec IA"

# Variables d'environnement
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Installer les dépendances système
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    wget \
    curl \
    gcc \
    g++ \
    make \
    libpq-dev \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    chromium \
    chromium-driver \
    tor \
    && rm -rf /var/lib/apt/lists/*

# Créer le répertoire de l'application
WORKDIR /app

# Copier les requirements
COPY requirements.txt .

# Installer les dépendances Python
RUN pip install --no-cache-dir -r requirements.txt

# Installer SQLMap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap

# Installer Nuclei
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip && \
    unzip nuclei_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_linux_amd64.zip

# Installer Subfinder
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_amd64.zip && \
    unzip subfinder_linux_amd64.zip && \
    mv subfinder /usr/local/bin/ && \
    rm subfinder_linux_amd64.zip

# Copier le code de l'application
COPY . .

# Créer les dossiers nécessaires
RUN mkdir -p logs rapports/output base_de_donnees

# Exposer le port
EXPOSE 5000

# Commande de démarrage
CMD ["python", "main.py"]

