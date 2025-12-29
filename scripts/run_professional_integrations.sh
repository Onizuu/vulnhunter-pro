#!/bin/bash

# Script de démonstration des intégrations professionnelles VulnHunter Pro
# Connectors pour Burp Suite, OWASP ZAP, Nessus, OpenVAS, Metasploit

echo "🔗 VULNHUNTER PRO - INTÉGRATIONS PROFESSIONNELLES"
echo "================================================="
echo ""
echo "🎯 Cette démo montre l'orchestration multi-outils:"
echo "   ✅ Burp Suite API (analyse web spécialisée)"
echo "   ✅ OWASP ZAP API (scanning automatisé)"
echo "   ✅ Nessus API (audit infrastructure)"
echo "   ✅ OpenVAS (sécurité open source)"
echo "   ✅ Metasploit (exploitation avancée)"
echo ""
echo "🚀 Workflow démontré:"
echo "   1. Configuration des connecteurs"
echo "   2. Scan initial VulnHunter"
echo "   3. Envoi aux outils professionnels"
echo "   4. Collecte et consolidation des résultats"
echo "   5. Rapport intégré final"
echo ""

# Vérifier que Python est disponible
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 n'est pas installé"
    exit 1
fi

echo "🔧 Lancement de la démonstration d'intégrations..."
echo ""

# Lancer la démonstration
python3 demo_professional_integrations.py

echo ""
echo "🎉 DÉMONSTRATION TERMINÉE !"
echo ""
echo "💡 Pour utiliser en production:"
echo "   1. Installer et configurer les outils professionnels"
echo "   2. Définir les variables d'environnement"
echo "   3. Tester la connectivité individuelle"
echo "   4. Lancer des scans sur de vraies cibles"
echo ""
echo "🔗 VulnHunter Pro peut maintenant orchestrer votre arsenal sécurité !"
