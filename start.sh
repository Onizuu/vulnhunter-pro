#!/bin/bash

# Script de démarrage VulnHunter Pro
# Démarre l'application complète avec interface web

echo "🚀 VULNHUNTER PRO v4.2 - DÉMARRAGE"
echo "=================================="
echo ""

# Vérifier si Python est installé
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    echo "   Installez Python 3.9+ depuis https://python.org"
    exit 1
fi

# Vérifier la version Python
PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
if (( $(echo "$PYTHON_VERSION < 3.9" | bc -l) )); then
    echo "❌ Python $PYTHON_VERSION détecté - Python 3.9+ requis"
    echo "   Mettez à jour Python depuis https://python.org"
    exit 1
fi

echo "✅ Python $PYTHON_VERSION détecté"

# Installer les dépendances si besoin
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
fi

echo "🔧 Activation de l'environnement virtuel..."
source venv/bin/activate

echo "📦 Installation des dépendances..."
pip install -q -r requirements.txt

# Variables d'environnement
export FLASK_APP=main.py
export FLASK_ENV=development

# Configuration IA (optionnel)
if [ -z "$OPENAI_API_KEY" ]; then
    echo "⚠️  OPENAI_API_KEY non configurée - Mode sans IA activé"
    echo "   Les fonctionnalités IA seront limitées"
    echo "   Configurez votre clé API OpenAI pour fonctionnalités complètes"
fi

echo ""
echo "🎯 DÉMARRAGE DE VULNHUNTER PRO"
echo "=============================="
echo ""
echo "🌐 Interface web: http://localhost:5000"
echo "📊 Dashboard: http://localhost:5000/dashboard"
echo "🔗 API: http://localhost:5000/api"
echo ""
echo "⚠️  Utilisez Ctrl+C pour arrêter le serveur"
echo ""

# Démarrer l'application
python3 main.py
