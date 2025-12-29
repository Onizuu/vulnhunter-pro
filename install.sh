#!/bin/bash

# Script d'installation VulnHunter Pro
# Installe toutes les dépendances et configure l'environnement

echo "📦 INSTALLATION VULNHUNTER PRO v4.2"
echo "==================================="
echo ""

# Vérifier le système d'exploitation
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macOS"
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    OS="Windows"
else
    OS="Inconnu"
fi

echo "🖥️  Système détecté: $OS"
echo ""

# Vérifier Python
echo "🐍 Vérification de Python..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    echo ""
    echo "📋 INSTRUCTIONS D'INSTALLATION:"
    echo ""
    if [[ "$OS" == "macOS" ]]; then
        echo "🍎 macOS:"
        echo "   brew install python3"
        echo "   # ou téléchargez depuis https://python.org"
    elif [[ "$OS" == "Linux" ]]; then
        echo "🐧 Linux:"
        echo "   Ubuntu/Debian: sudo apt install python3 python3-pip python3-venv"
        echo "   CentOS/RHEL: sudo yum install python3 python3-pip"
        echo "   Arch: sudo pacman -S python python-pip"
    else
        echo "   Téléchargez Python 3.9+ depuis https://python.org"
    fi
    exit 1
fi

# Vérifier la version Python
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if (( $(echo "$PYTHON_VERSION < 3.9" | bc -l 2>/dev/null || echo "1") )); then
    echo "❌ Python $PYTHON_VERSION détecté - Python 3.9+ requis"
    echo "   Mettez à jour Python depuis https://python.org"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION détecté"

# Installer bc si nécessaire (pour les comparaisons)
if ! command -v bc &> /dev/null && [[ "$OS" == "macOS" ]]; then
    echo "📦 Installation de bc (nécessaire pour macOS)..."
    if command -v brew &> /dev/null; then
        brew install bc
    fi
fi

# Créer l'environnement virtuel
echo ""
echo "🔧 CRÉATION DE L'ENVIRONNEMENT VIRTUEL"
echo "======================================"

if [ -d "venv" ]; then
    echo "⚠️  Environnement virtuel existant détecté"
    read -p "   Voulez-vous le recréer ? (o/N): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Oo]$ ]]; then
        rm -rf venv
        echo "🗑️  Ancien environnement supprimé"
    fi
fi

if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "❌ Échec de création de l'environnement virtuel"
        exit 1
    fi
fi

echo "✅ Environnement virtuel créé"

# Activer l'environnement
echo ""
echo "🔧 ACTIVATION ET INSTALLATION"
echo "============================="

source venv/bin/activate

# Mettre à jour pip
echo "⬆️  Mise à jour de pip..."
pip install -q --upgrade pip

# Installer les dépendances Python
echo "📦 Installation des dépendances Python..."
pip install -q -r requirements.txt

if [ $? -ne 0 ]; then
    echo "❌ Échec d'installation des dépendances Python"
    echo ""
    echo "🔧 SOLUTIONS POSSIBLES:"
    echo "   1. Vérifiez votre connexion internet"
    echo "   2. Installez manuellement: pip install flask requests beautifulsoup4 ..."
    echo "   3. Sur macOS: xcode-select --install"
    exit 1
fi

echo "✅ Dépendances Python installées"

# Installer les outils système (optionnel)
echo ""
echo "🔧 OUTILS SYSTÈME OPTIONNELS"
echo "============================"

TOOLS_INSTALLED=0

# Nmap
if ! command -v nmap &> /dev/null; then
    echo "📦 Installation de Nmap (recommandé pour les scans de ports)..."
    if [[ "$OS" == "macOS" ]]; then
        if command -v brew &> /dev/null; then
            brew install nmap
            TOOLS_INSTALLED=$((TOOLS_INSTALLED + 1))
        fi
    elif [[ "$OS" == "Linux" ]]; then
        if command -v apt &> /dev/null; then
            sudo apt install -y nmap
            TOOLS_INSTALLED=$((TOOLS_INSTALLED + 1))
        elif command -v yum &> /dev/null; then
            sudo yum install -y nmap
            TOOLS_INSTALLED=$((TOOLS_INSTALLED + 1))
        fi
    fi
else
    echo "✅ Nmap déjà installé"
fi

# Masscan (ultra-rapide)
if ! command -v masscan &> /dev/null; then
    echo "📦 Masscan non trouvé (optionnel - ultra-rapide pour scans de ports)"
    echo "   Installation manuelle recommandée pour performances optimales"
fi

# Subfinder (énumération sous-domaines)
if ! command -v subfinder &> /dev/null; then
    echo "📦 Subfinder non trouvé (optionnel - énumération avancée sous-domaines)"
    echo "   Téléchargez depuis: https://github.com/projectdiscovery/subfinder"
fi

# Configuration finale
echo ""
echo "⚙️  CONFIGURATION FINALE"
echo "========================"

# Créer le fichier .env si inexistant
if [ ! -f ".env" ]; then
    echo "📝 Création du fichier de configuration .env..."
    cat > .env << EOF
# Configuration VulnHunter Pro

# Clé secrète Flask (changez en production)
SECRET_KEY=vulnhunter-secret-key-change-in-production

# Configuration IA (optionnel)
# OPENAI_API_KEY=sk-your-openai-key-here
# ANTHROPIC_API_KEY=sk-ant-your-anthropic-key-here

# Configuration base de données (optionnel)
# DATABASE_URL=postgresql://user:pass@localhost/vulnhunter

# Configuration Redis (optionnel pour cache)
# REDIS_URL=redis://localhost:6379

# Configuration notifications (optionnel)
# DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
# SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
# TELEGRAM_BOT_TOKEN=your-bot-token
# TELEGRAM_CHAT_ID=your-chat-id

# Configuration logging
LOG_LEVEL=INFO
LOG_FILE=vulnhunter.log

# Configuration scans
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=300
REQUEST_TIMEOUT=10

# Configuration sécurité
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=60
EOF
    echo "✅ Fichier .env créé"
fi

# Rendre les scripts exécutables
echo "🔧 Configuration des permissions..."
chmod +x install.sh start.sh run_*.sh test_*.sh demo_*.sh 2>/dev/null || true

# Test d'importation
echo ""
echo "🧪 TEST D'IMPORTATION"
echo "===================="

python3 -c "
try:
    import flask, requests, bs4, aiohttp
    print('✅ Imports de base réussis')
    import plotly, networkx
    print('✅ Imports avancés réussis')
    from core.models import Vulnerabilite
    from core.executive_reporting import OrchestrateurReporting
    print('✅ Imports VulnHunter réussis')
    print('🎉 Installation complète réussie !')
except ImportError as e:
    print(f'❌ Erreur d\'import: {e}')
    exit(1)
"

if [ $? -eq 0 ]; then
    echo ""
    echo "🎉 INSTALLATION TERMINÉE AVEC SUCCÈS !"
    echo "======================================"
    echo ""
    echo "🚀 Pour démarrer VulnHunter Pro:"
    echo "   ./start.sh"
    echo ""
    echo "🌐 Interface web: http://localhost:5000"
    echo "📊 Dashboard: http://localhost:5000/dashboard"
    echo ""
    echo "📋 Scripts disponibles:"
    echo "   • ./start.sh              # Démarrer l'application"
    echo "   • ./run_attack_chains.sh  # Démo chaînes d'attaque"
    echo "   • ./run_executive_reporting.sh  # Démo reporting"
    echo "   • ./test_*.py             # Tests unitaires"
    echo ""
    echo "⚙️  Configuration (éditez .env):"
    echo "   • Clés API IA pour fonctionnalités avancées"
    echo "   • Webhooks notifications (Discord/Slack/Telegram)"
    echo "   • Configuration base de données"
    echo ""
    echo "🆘 Support:"
    echo "   • README.md pour documentation complète"
    echo "   • AMELIORATIONS_PROPOSEES.md pour v5.0"
    echo "   • PROJET_FINAL_RECAP.md pour récapitulatif"
    echo ""
    echo "🎯 VulnHunter Pro v4.2 est prêt à révolutionner votre cybersécurité !"
    echo ""
    echo "🏆 BONNE CHASSE AUX VULNÉRABILITÉS ! 🏆"
else
    echo ""
    echo "❌ ERREUR D'INSTALLATION"
    echo "========================"
    echo "Vérifiez les logs ci-dessus et réessayez"
    exit 1
fi