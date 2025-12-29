#!/bin/bash

# Script de démonstration des métriques de conformité VulnHunter Pro
# OWASP Risk Rating, CVSS v4, PCI-DSS, GDPR, HIPAA, benchmarks, heatmaps

echo "📊 VULNHUNTER PRO - MÉTRIQUES DE CONFORMITÉ"
echo "=========================================="
echo ""
echo "🎯 Cette démo montre les capacités d'analyse de conformité:"
echo "   ✅ OWASP Risk Rating Methodology (scores 0-81)"
echo "   ✅ CVSS v3.1 Score Calculation (vecteurs complets)"
echo "   ✅ Compliance Checks (PCI-DSS, GDPR, HIPAA)"
echo "   ✅ Industry Benchmarks (positionnement sectoriel)"
echo "   ✅ Risk Heatmaps (visualisation matricielle)"
echo ""
echo "📋 Scénario: Audit complet d'une application e-commerce"
echo "   - Analyse OWASP + CVSS de 8 vulnérabilités"
echo "   - Vérification conformité réglementaire"
echo "   - Comparaison benchmarks industry"
echo "   - Génération heatmap de risque"
echo "   - Rapport executive détaillé"
echo ""

# Vérifier que Python est disponible
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    exit 1
fi

echo "📊 Lancement de l'analyse de conformité..."
echo ""

# Lancer la démonstration
python3 demo_compliance_metrics.py

echo ""
echo "🎉 DÉMONSTRATION TERMINÉE !"
echo ""
echo "💡 Pour utiliser en production:"
echo "   1. Intégrer dans vos workflows de sécurité"
echo "   2. Générer rapports pour la direction"
echo "   3. Utiliser pour audits de conformité"
echo "   4. Monitorer la maturité sécurité"
echo ""
echo "📊 VulnHunter Pro peut maintenant quantifier et prioriser vos risques !"
