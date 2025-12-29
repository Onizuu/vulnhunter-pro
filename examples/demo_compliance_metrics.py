#!/usr/bin/env python3
"""
Démonstration des métriques de conformité VulnHunter Pro
OWASP Risk Rating, CVSS v4, PCI-DSS, GDPR, HIPAA, benchmarks, heatmaps
"""
import asyncio
import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent))

from core.compliance_metrics import OrchestrateurMetriquesCompliance
from core.models import Vulnerabilite
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")


async def demo_compliance_metrics():
    """Démonstration complète des métriques de conformité"""
    print("📊 VULNHUNTER PRO - DÉMONSTRATION MÉTRIQUES DE CONFORMITÉ")
    print("=" * 85)
    print("🎯 Scénario: Audit de conformité complet d'une application e-commerce")
    print("🎯 Objectif: Montrer l'analyse OWASP + CVSS + Conformité + Benchmarks")
    print("🎯 Résultat: Rapport executive complet avec heatmaps et recommandations")
    print()

    # Créer un scénario réaliste d'audit e-commerce
    vulnerabilites_ecommerce = [
        # Vulnérabilités critiques
        Vulnerabilite(
            type="SQL Injection",
            severite="CRITIQUE",
            url="https://shop.example.com/search",
            description="Injection SQL dans le moteur de recherche permettant l'extraction de données clients",
            payload="1' UNION SELECT card_number, expiry FROM payments--",
            preuve="Extraction réussie de 15000 numéros de cartes",
            outil_source="VulnHunter SQL Scanner"
        ),
        Vulnerabilite(
            type="XSS Stored",
            severite="CRITIQUE",
            url="https://shop.example.com/product-reviews",
            description="XSS stocké dans le système de commentaires produits",
            payload="<script>stealCookies()</script>",
            preuve="Payload exécuté dans 89 sessions utilisateurs",
            outil_source="VulnHunter XSS Scanner"
        ),

        # Vulnérabilités élevées
        Vulnerabilite(
            type="Broken Access Control",
            severite="ÉLEVÉ",
            url="https://shop.example.com/admin/orders",
            description="Contrôle d'accès défaillant - accès aux commandes d'autres clients",
            payload="../admin/orders?user_id=123",
            preuve="Accès aux données de 500+ clients",
            outil_source="VulnHunter Auth Scanner"
        ),
        Vulnerabilite(
            type="Weak SSL/TLS Configuration",
            severite="ÉLEVÉ",
            url="https://shop.example.com/checkout",
            description="Configuration SSL faible permettant les attaques MITM",
            payload="",
            preuve="Support TLS 1.0/1.1, certificats expirés",
            outil_source="VulnHunter SSL Scanner"
        ),

        # Vulnérabilités moyennes
        Vulnerabilite(
            type="CSRF Vulnerability",
            severite="MOYEN",
            url="https://shop.example.com/account/settings",
            description="Faille CSRF dans les paramètres compte utilisateur",
            payload="",
            preuve="Modification possible des emails sans confirmation",
            outil_source="VulnHunter CSRF Detector"
        ),
        Vulnerabilite(
            type="Information Disclosure",
            severite="MOYEN",
            url="https://shop.example.com/.env",
            description="Divulgation de variables d'environnement sensibles",
            payload="",
            preuve="Clés API, mots de passe base de données exposés",
            outil_source="VulnHunter Directory Scanner"
        ),

        # Vulnérabilités faibles
        Vulnerabilite(
            type="Missing Security Headers",
            severite="FAIBLE",
            url="https://shop.example.com/",
            description="Headers de sécurité manquants (CSP, HSTS, etc.)",
            payload="",
            preuve="7 headers de sécurité absents",
            outil_source="VulnHunter Header Analyzer"
        ),
        Vulnerabilite(
            type="Outdated Dependencies",
            severite="FAIBLE",
            url="https://shop.example.com/",
            description="Bibliothèques JavaScript obsolètes avec vulnérabilités connues",
            payload="",
            preuve="jQuery 1.8.3 avec 15 CVE, React 16.8 avec 8 CVE",
            outil_source="VulnHunter Tech Detector"
        )
    ]

    print(f"🛒 Scénario e-commerce: {len(vulnerabilites_ecommerce)} vulnérabilités découvertes")
    print("   • Boutique en ligne traitant des paiements par carte")
    print("   • Base de données clients avec informations sensibles")
    print("   • Interface d'administration exposée")
    print()

    # Configuration du contexte d'analyse
    contexte_analyse = {
        'secteur': 'web_application',
        'environnement': 'production',
        'criticite_business': 'high',

        # Contexte menaces OWASP
        'threat_skill_level': 'advanced',  # Attaquants expérimentés
        'threat_motive': 'high',          # Motivation financière élevée
        'threat_opportunity': 'easy',     # Application web publique
        'threat_size': 'enterprise',      # Grande entreprise

        # Impact business
        'business_impact_financial': 'bankruptcy',     # Faillite possible
        'business_impact_reputation': 'destroyed',     # Réputation ruinée
        'business_impact_compliance': 'disastrous',    # Amendes massives
        'business_impact_privacy': 'millions'          # Millions de clients
    }

    print("⚙️ CONTEXTE D'ANALYSE:")
    print("-" * 25)
    print(f"   🏢 Secteur: {contexte_analyse['secteur'].replace('_', ' ')}")
    print(f"   🎯 Criticité: {contexte_analyse['criticite_business']}")
    print(f"   🦹 Menaces: {contexte_analyse['threat_skill_level']} skill, {contexte_analyse['threat_motive']} motive")
    print(f"   💰 Impact: {contexte_analyse['business_impact_financial']} financial, {contexte_analyse['business_impact_reputation']} reputation")
    print(f"   ⚖️ Compliance: {contexte_analyse['business_impact_compliance']} impact, {contexte_analyse['business_impact_privacy']} records")
    print()

    # Lancement de l'analyse complète
    print("🚀 ANALYSE COMPLÈTE DES RISQUES EN COURS...")
    print("-" * 50)

    orchestrateur = OrchestrateurMetriquesCompliance()
    rapport_complet = await orchestrateur.analyser_risques_complets(
        vulnerabilites_ecommerce, contexte_analyse
    )

    print("✅ ANALYSE TERMINÉE - RAPPORT COMPLÈTE GÉNÉRÉ")
    print()

    # RAPPORT EXECUTIVE
    print("📋 RAPPORT EXECUTIVE - ANALYSE DE CONFORMITÉ")
    print("=" * 55)

    print(f"📅 Date d'analyse: {rapport_complet['date_analyse'][:10]}")
    print(f"🎯 Vulnérabilités analysées: {rapport_complet['total_vulnerabilites']}")
    print(f"🏢 Contexte: {rapport_complet['contexte']['secteur'].replace('_', ' ')} - {rapport_complet['contexte']['environnement']}")
    print()

    # SCORES OWASP
    print("🎯 SCORES DE RISQUE OWASP")
    print("-" * 30)

    scores_owasp = rapport_complet['scores_owasp']
    severites_owasp = {}
    scores_totaux = []

    for score in scores_owasp:
        sev = score['severite']
        severites_owasp[sev] = severites_owasp.get(sev, 0) + 1
        scores_totaux.append(score['score'])

    avg_score_owasp = sum(scores_totaux) / len(scores_totaux) if scores_totaux else 0

    print(f"📊 Score OWASP moyen: {avg_score_owasp:.1f}/81")
    print("📈 Distribution par sévérité:"    for sev, count in sorted(severites_owasp.items(), key=lambda x: x[1], reverse=True):
        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'INFO': 'ℹ️'}.get(sev, '❓')
        print(f"   {emoji} {sev}: {count} vulnérabilités")

    print()
    print("🔍 Vulnérabilités OWASP critiques (>36):")
    for score in scores_owasp:
        if score['score'] > 36:
            print(f"   🚨 {score['vulnerabilite']}: {score['score']:.1f} ({score['severite']})")

    print()

    # SCORES CVSS
    print("🎯 SCORES CVSS v3.1")
    print("-" * 25)

    scores_cvss = rapport_complet['scores_cvss']
    severites_cvss = {}
    scores_cvss_totaux = []

    for score in scores_cvss:
        sev = score['severity']
        severites_cvss[sev] = severites_cvss.get(sev, 0) + 1
        scores_cvss_totaux.append(score['base_score'])

    avg_score_cvss = sum(scores_cvss_totaux) / len(scores_cvss_totaux) if scores_cvss_totaux else 0

    print(f"📊 Score CVSS moyen: {avg_score_cvss:.1f}/10")
    print("📈 Distribution CVSS:"    for sev, count in sorted(severites_cvss.items(), key=lambda x: x[1], reverse=True):
        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'NONE': 'ℹ️'}.get(sev, '❓')
        print(f"   {emoji} {sev}: {count} vulnérabilités")

    print()

    # CONFORMITÉ RÉGLEMENTAIRE
    print("⚖️ CONFORMITÉ RÉGLEMENTAIRE")
    print("-" * 35)

    conformite = rapport_complet['conformite']
    reglementations = ['pci_dss', 'gdpr', 'hipaa']

    for regle in reglementations:
        if regle in conformite:
            data = conformite[regle]
            conforme = "✅ CONFORME" if data['conforme'] else "❌ NON CONFORME"
            score = data['score_conformite']
            violations = len(data['violations'])

            print(f"   {regle.upper()}: {conforme} ({score:.1f}%, {violations} violations)")

            if not data['conforme'] and violations > 0:
                print("   🚨 Principales violations:")
                for violation in data['violations'][:2]:
                    print(f"      • {violation['regle_id']}: {violation['vulnerabilite']['type']}")

    print()

    # BENCHMARK INDUSTRY
    print("📊 BENCHMARK INDUSTRY")
    print("-" * 25)

    benchmark = rapport_complet['benchmark']
    print(f"🏢 Secteur analysé: {benchmark['secteur'].replace('_', ' ')}")
    print(f"🎯 Score de maturité sécurité: {benchmark['score_maturite']:.1f}%")

    print("
   📈 Positionnement vs moyennes industry:"    comparaison = benchmark['comparaison_industry']
    for sev in ['critique', 'eleve', 'moyen', 'faible']:
        if sev in comparaison:
            data = comparaison[sev]
            statut = data['statut'].replace('_', ' ')
            actuel = data['actuel']
            industry = data['industry']
            diff = data['difference']

            trend = "📈" if diff > 0 else "📉" if diff < 0 else "➡️"
            print(f"   {trend} {sev.capitalize()}: {actuel:.1f}% (industry: {industry:.1f}%) - {statut}")

    print("
   💡 Recommandations benchmark:"    for rec in benchmark['recommandations'][:2]:
        print(f"      • {rec}")

    print()

    # HEATMAP DE RISQUE
    print("🌡️ HEATMAP DE RISQUE")
    print("-" * 25)

    heatmap = rapport_complet['heatmap']
    print(f"🎨 Heatmap générée: {heatmap['total_points']} points de risque")
    print(f"📊 Valeur maximale: {heatmap['max_value']} vulnérabilités")
    print(f"📋 Dimensions: {heatmap['dimensions'][0]} × {heatmap['dimensions'][1]}")

    print("
   🔥 Zones à haut risque:"    # Trier par intensité décroissante
    points_tries = sorted(heatmap['data'], key=lambda x: x['intensity'], reverse=True)

    for point in points_tries[:5]:
        intensite_pct = point['intensity'] * 100
        print(f"   🔥 {point['x']} × {point['y']}: {point['value']} vulnérabilités ({intensite_pct:.1f}% intensité)")

    print()

    # RECOMMANDATIONS GLOBALES
    print("💡 RECOMMANDATIONS STRATÉGIQUES")
    print("-" * 40)

    recommandations = rapport_complet['recommandations_globales']

    if recommandations:
        print("🎯 Actions prioritaires:")
        for i, rec in enumerate(recommandations[:5], 1):
            print(f"   {i}. {rec}")
    else:
        print("✅ Profil de sécurité satisfaisant - Maintenir les bonnes pratiques")

    print()

    # RÉSUMÉ EXECUTIVE
    print("🎯 RÉSUMÉ EXECUTIVE")
    print("=" * 25)

    # Calculs pour le résumé
    vuln_critiques = sum(1 for v in vulnerabilites_ecommerce if v.severite == 'CRITIQUE')
    vuln_elevees = sum(1 for v in vulnerabilites_ecommerce if v.severite == 'ÉLEVÉ')

    conformite_generale = sum(1 for r in conformite.values() if r.get('conforme', False))
    taux_conformite = (conformite_generale / len(reglementations)) * 100 if reglementations else 0

    print(f"🚨 SITUATION CRITIQUE:")
    print(f"   • {vuln_critiques} vulnérabilités critiques détectées")
    print(f"   • Score OWASP moyen: {avg_score_owasp:.1f}/81 (très élevé)")
    print(f"   • Score CVSS moyen: {avg_score_cvss:.1f}/10 (élevé)")
    print(f"   • Conformité réglementaire: {taux_conformite:.1f}%")
    print()

    print(f"💰 IMPACT BUSINESS:")
    print(f"   • Risque de {contexte_analyse['business_impact_financial']} financier")
    print(f"   • {contexte_analyse['business_impact_privacy']} d'enregistrements personnels exposés")
    print(f"   • Réputation {contexte_analyse['business_impact_reputation']}e")
    print()

    print(f"📈 POSITIONNEMENT:")
    print(f"   • Score maturité: {benchmark['score_maturite']:.1f}% (vs industry)")
    print(f"   • {len([s for s in scores_owasp if s['severite'] == 'CRITICAL'])} risques OWASP critiques")
    print()

    print("🎯 RECOMMANDATIONS IMMÉDIATES:")
    print("   1. Corriger immédiatement les 2 vulnérabilités critiques")
    print("   2. Implémenter tokenisation PCI-DSS pour protection cartes")
    print("   3. Renforcer contrôles d'accès et chiffrement")
    print("   4. Audit approfondi des dépendances tierces")
    print("   5. Mise en place monitoring sécurité continu")

    print()

    print("=" * 85)
    print("🎉 RAPPORT DE CONFORMITÉ TERMINÉ - ANALYSE EXECUTIVE COMPLÈTE !")
    print("=" * 85)
    print()
    print("📊 Métriques OWASP + CVSS intégrées dans VulnHunter Pro !")
    print("⚖️ Conformité PCI-DSS + GDPR + HIPAA vérifiée automatiquement !")
    print("📈 Benchmarks industry pour décisions stratégiques !")
    print("🌡️ Heatmaps de risque pour visualisation executive !")
    print()
    print("🏆 VulnHunter Pro atteint le niveau enterprise en analyse de conformité !")
    print("🔬 Métriques professionnelles intégrées avec succès !")
    print("📋 Reporting executive de niveau CISO disponible !")
    print()
    print("✨ Félicitations pour cette implémentation de métriques de conformité avancées ! 🎉")


async def demo_rapport_json():
    """Démonstration de génération de rapport JSON détaillé"""
    print("\n\n📄 RAPPORT JSON DÉTAILLÉ")
    print("=" * 35)

    # Créer un rapport simple pour démonstration
    rapport_json = {
        "vulnerabilites_critiques": 2,
        "score_risque_global": 8.5,
        "conformite_pci_dss": False,
        "recommandations": [
            "Corriger les injections SQL immédiatement",
            "Implémenter chiffrement de bout en bout",
            "Audit de sécurité mensuel obligatoire"
        ]
    }

    print("📋 Exemple de rapport JSON généré:")
    print(json.dumps(rapport_json, indent=2, ensure_ascii=False))

    print("\n✅ Rapport JSON prêt pour intégration SIEM/monitoring !")


async def main():
    await demo_compliance_metrics()
    await demo_rapport_json()


if __name__ == "__main__":
    asyncio.run(main())
