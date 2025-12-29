#!/bin/bash

# Script pour relancer VulnHunter Pro avec les nouvelles améliorations
# Créé automatiquement par l'assistant

echo "🔄 Redémarrage de VulnHunter Pro..."
echo ""

# Arrêter les instances en cours
pkill -f "python.*main.py" 2>/dev/null
sleep 2

# Aller dans le bon dossier
cd "$(dirname "$0")"

# Relancer l'application
echo "🚀 Démarrage avec les améliorations:"
echo "  ✅ Déduplication par URL + paramètre"
echo "  ✅ Détection XSS améliorée (searchFor, etc.)"
echo ""

./start-sans-ia.sh

