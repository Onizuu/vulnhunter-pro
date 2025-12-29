#!/bin/bash

# Script de démonstration du reporting exécutif avancé VulnHunter Pro
# Dashboards interactifs, time-series, trend analysis, executive summaries, technical deep-dives, compliance reports

echo "📊 VULNHUNTER PRO - REPORTING EXÉCUTIF AVANCÉ"
echo "==============================================="
echo ""
echo "🎯 Cette démo montre le système de reporting professionnel:"
echo "   ✅ Dashboards interactifs avec graphiques Plotly"
echo "   ✅ Time-series analysis avec prédictions"
echo "   ✅ Trend analysis sur l'évolution des risques"
echo "   ✅ Executive summaries pour la direction"
echo "   ✅ Technical deep-dives pour les équipes IT"
echo "   ✅ Compliance reports multi-réglementaires"
echo ""
echo "📋 Scénario: Génération complète de rapports enterprise"
echo "   - 9 vulnérabilités analysées sur entreprise e-commerce"
echo "   - Historique de 7 scans sur 7 mois"
echo "   - 3 réglementations auditées (GDPR, PCI-DSS, ISO27001)"
echo "   - Chaînes d'attaque intégrées"
echo "   - Exports multi-formats (JSON, HTML)"
echo ""

# Vérifier que Python est disponible
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    exit 1
fi

echo "📊 Lancement du reporting exécutif avancé..."
echo ""

# Lancer la démonstration
python3 demo_executive_reporting.py

echo ""
echo "🎉 DÉMONSTRATION TERMINÉE !"
echo ""
echo "💡 Pour utiliser en production:"
echo "   1. Intégrer dans vos workflows SOC"
echo "   2. Générer rapports périodiques pour le board"
echo "   3. Partager avec les auditeurs externes"
echo "   4. Utiliser les prédictions pour la planification"
echo ""
echo "📊 VulnHunter Pro génère maintenant des rapports de niveau CISO !"
