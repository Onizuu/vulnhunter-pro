#!/bin/bash

# Script de démonstration rapide du système distribué VulnHunter Pro
# Architecture distribuée pour scan de gros sites

echo "🚀 VULNHUNTER PRO - DÉMONSTRATION SYSTÈME DISTRIBUÉ"
echo "=================================================="
echo ""
echo "🎯 Cette démo montre les capacités de scan distribué:"
echo "   ✅ Multi-threading avancé (15 threads + 3 processus)"
echo "   ✅ Load balancing intelligent"
echo "   ✅ Rate limiting adaptatif"
echo "   ✅ Proxy rotation automatique"
echo "   ✅ Architecture haute performance"
echo ""
echo "📊 Scénario: Scan distribué d'un gros site e-commerce"
echo "   - 125+ pages simulées"
echo "   - Load balancing automatisé"
echo "   - Métriques temps réel"
echo ""

# Vérifier que Python est disponible
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    exit 1
fi

echo "🐍 Lancement du scan distribué..."
echo ""

# Lancer la démonstration
python3 demo_distributed_scan.py

echo ""
echo "🎉 DÉMONSTRATION TERMINÉE !"
echo ""
echo "💡 Pour utiliser en production:"
echo "   1. Configurez vos vrais proxies dans le code"
echo "   2. Ajustez les URLs cibles réelles"
echo "   3. Scalez le nombre de workers selon vos ressources"
echo ""
echo "🚀 Prêt pour scanner les plus gros sites du web !"
