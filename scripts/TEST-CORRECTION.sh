#!/bin/bash

# Script de test de la correction VulnHunter Pro
# Test sur OWASP Juice Shop pour vérifier que les faux positifs sont éliminés

echo "🧪 TEST DE CORRECTION - VULNHUNTER PRO"
echo "====================================="
echo ""
echo "🎯 Objectif: Vérifier que Juice Shop n'affiche plus 95 faux positifs"
echo "🎯 Attendu: ~5-15 vraies vulnérabilités maximum (pas 95!)"
echo ""
echo "📋 Rappel du problème précédent:"
echo "   ❌ 95 vulnérabilités (92 critiques)"
echo "   ❌ Toutes sur des URLs PHP qui n'existent pas"
echo "   ❌ Scanner testait des pages d'erreur 404"
echo ""
echo "✅ Correction appliquée:"
echo "   ✅ Filtrage des URLs avant scan"
echo "   ✅ Exclusion des pages d'erreur"
echo "   ✅ Vérification contenu réel"
echo ""

# Demander confirmation
read -p "🚀 Lancer le test sur Juice Shop ? (o/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Oo]$ ]]; then
    echo ""
    echo "🔍 Lancement du scan corrigé..."
    echo "   URL: https://juice-shop.herokuapp.com/"
    echo "   Durée estimée: 2-3 minutes"
    echo ""

    # Lancer VulnHunter Pro
    ./RELANCER-SCAN.sh

    echo ""
    echo "📊 RÉSULTATS ATTENDUS APRÈS CORRECTION:"
    echo "======================================="
    echo ""
    echo "✅ AVANT (PROBLÉMATIQUE):"
    echo "   - 95 vulnérabilités totales"
    echo "   - 92 critiques (impossible)"
    echo "   - URLs PHP sur app React"
    echo ""
    echo "🎯 APRÈS (CORRIGÉ):"
    echo "   - ~5-15 vraies vulnérabilités"
    echo "   - Quelques critiques réelles"
    echo "   - Seulement URLs existantes"
    echo ""
    echo "🔍 Vérifiez dans les logs:"
    echo "   - 'Filtrage des X URLs découvertes'"
    echo "   - 'Y endpoints existent réellement'"
    echo "   - Nombre réaliste de vulnérabilités"
    echo ""

else
    echo ""
    echo "❌ Test annulé"
    echo ""
    echo "💡 Pour lancer manuellement:"
    echo "   ./RELANCER-SCAN.sh"
    echo "   URL: https://juice-shop.herokuapp.com/"
    echo ""
fi
