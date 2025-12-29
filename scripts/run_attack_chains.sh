#!/bin/bash

# Script de démonstration de l'analyse de chaînes d'attaque VulnHunter Pro
# Attack trees automatiques, privilege escalation, lateral movement, business impact

echo "🔗 VULNHUNTER PRO - ANALYSE DE CHAÎNES D'ATTAQUE"
echo "================================================"
echo ""
echo "🎯 Cette démo montre l'analyse prédictive de menaces:"
echo "   ✅ Attack trees automatiques (arbres d'attaque)"
echo "   ✅ Privilege escalation paths (chemins d'escalade)"
echo "   ✅ Lateral movement analysis (mouvement latéral)"
echo "   ✅ Business impact calculation (impact business)"
echo "   ✅ Remediation priority scoring (priorités remédiation)"
echo ""
echo "📋 Scénario: Reconstruction complète d'une cyberattaque"
echo "   - 7 vulnérabilités interconnectées analysées"
echo "   - Arbres d'attaque automatiques générés"
echo "   - Escalade de privilèges cartographiée"
echo "   - Impact business quantifié (€)"
echo "   - Priorités de correction définies"
echo "   - Rapport stratégique executive"
echo ""

# Vérifier que Python est disponible
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    exit 1
fi

echo "🔗 Lancement de l'analyse de chaînes d'attaque..."
echo ""

# Lancer la démonstration
python3 demo_attack_chains.py

echo ""
echo "🎉 DÉMONSTRATION TERMINÉE !"
echo ""
echo "💡 Pour utiliser en production:"
echo "   1. Intégrer dans vos workflows SOC"
echo "   2. Générer rapports pour le CISO"
echo "   3. Prioriser les budgets de sécurité"
echo "   4. Préparer les plans de réponse"
echo ""
echo "🔗 VulnHunter Pro peut maintenant prédire les vraies menaces !"
