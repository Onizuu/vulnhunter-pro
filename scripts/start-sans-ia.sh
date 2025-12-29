#!/bin/bash
# Démarrage rapide de VulnHunter Pro SANS IA

echo "🛡️  VulnHunter Pro - Mode Sans IA"
echo "=================================="
echo ""

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 n'est pas installé"
    exit 1
fi

echo "✅ Python $(python3 --version) détecté"

# Créer l'environnement virtuel si nécessaire
if [ ! -d "venv" ]; then
    echo "📦 Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activer l'environnement virtuel
echo "🔄 Activation de l'environnement virtuel..."
source venv/bin/activate

# Installer les dépendances minimales si nécessaire
if ! python -c "import flask" 2>/dev/null; then
    echo "📦 Installation des dépendances minimales..."
    pip install --upgrade pip --quiet
    pip install -r requirements-minimal.txt
fi

# Créer la configuration sans IA
if [ ! -f ".env" ]; then
    echo "⚙️  Création de la configuration sans IA..."
    cp config-sans-ia.env .env
    echo "✅ Fichier .env créé"
fi

# Créer les dossiers nécessaires
mkdir -p logs
mkdir -p rapports/output
mkdir -p base_de_donnees

echo ""
echo "=================================="
echo "✅ Configuration terminée !"
echo ""
echo "ℹ️  Mode Sans IA activé"
echo "   Les scans de base fonctionneront parfaitement"
echo "   sans génération de payloads IA"
echo ""
echo "🚀 Démarrage de VulnHunter Pro..."
echo "   Interface web: http://localhost:5000"
echo ""
echo "   Pour arrêter: Ctrl+C"
echo "=================================="
echo ""

# Lancer l'application
python main.py

