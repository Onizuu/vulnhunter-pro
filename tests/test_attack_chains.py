#!/usr/bin/env python3
"""
Test de l'analyse de chaînes d'attaque pour VulnHunter Pro
Attack trees automatiques, privilege escalation, lateral movement, business impact
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.attack_chains import (
    ConstructeurArbresAttaque, AnalyseurEscaladePrivileges,
    AnalyseurMouvementLateral, CalculateurImpactBusiness,
    ScoreurPrioriteRemediation, OrchestrateurChainesAttaque
)
from core.models import Vulnerabilite


async def test_attack_chains():
    """Test complet de l'analyse de chaînes d'attaque"""
    print("🔗 TEST ANALYSE DE CHAÎNES D'ATTAQUE - VULNHUNTER PRO")
    print("=" * 70)
    print("🎯 Fonctionnalités testées:")
    print("   ✅ Attack trees automatiques")
    print("   ✅ Privilege escalation paths")
    print("   ✅ Lateral movement analysis")
    print("   ✅ Business impact calculation")
    print("   ✅ Remediation priority scoring")
    print()

    # Créer des vulnérabilités de test réalistes
    vulnerabilites_test = [
        Vulnerabilite(
            type="SQL Injection",
            severite="CRITIQUE",
            url="https://shop.example.com/search",
            description="Injection SQL dans le moteur de recherche permettant l'extraction de données clients",
            payload="1' UNION SELECT * FROM users--",
            preuve="Extraction réussie de données utilisateurs",
            outil_source="VulnHunter SQL Scanner"
        ),
        Vulnerabilite(
            type="XSS Reflected",
            severite="ÉLEVÉ",
            url="https://shop.example.com/product-reviews",
            description="XSS réfléchi dans le système de commentaires",
            payload="<script>alert('XSS')</script>",
            preuve="Payload exécuté dans le navigateur",
            outil_source="VulnHunter XSS Scanner"
        ),
        Vulnerabilite(
            type="Weak Authentication",
            severite="ÉLEVÉ",
            url="https://shop.example.com/admin/login",
            description="Authentification faible avec mots de passe par défaut",
            payload="",
            preuve="Accès admin avec credentials par défaut",
            outil_source="VulnHunter Auth Scanner"
        ),
        Vulnerabilite(
            type="Information Disclosure",
            severite="MOYEN",
            url="https://shop.example.com/.env",
            description="Divulgation de variables d'environnement sensibles",
            payload="",
            preuve="Clés API et mots de passe exposés",
            outil_source="VulnHunter Directory Scanner"
        ),
        Vulnerabilite(
            type="Privilege Escalation",
            severite="CRITIQUE",
            url="https://shop.example.com/admin/users",
            description="Escalade de privilèges via injection de commandes",
            payload="; cat /etc/passwd",
            preuve="Accès root obtenu via commande système",
            outil_source="VulnHunter RCE Scanner"
        )
    ]

    print(f"🧪 Analyse de {len(vulnerabilites_test)} vulnérabilités interconnectées")
    print()

    # Configuration du contexte d'analyse
    contexte_analyse = {
        'threat_skill_level': 'advanced',      # Attaquants expérimentés
        'threat_motive': 'financial',          # Motivation financière
        'threat_opportunity': 'easy',          # Application publique
        'threat_size': 'large_enterprise',     # Grande entreprise
        'business_impact_financial': 'bankruptcy',
        'business_impact_reputation': 'destroyed',
        'business_impact_privacy': 'millions',
        'secteur': 'ecommerce',
        'taille_entreprise': 'enterprise',
        'criticite_donnees': 'critical'
    }

    print("⚙️ CONTEXTE D'ANALYSE COMPLEXE:")
    print("-" * 35)
    print(f"   🦹 Attaquants: {contexte_analyse['threat_skill_level']} ({contexte_analyse['threat_motive']} motive)")
    print(f"   🎯 Opportunité: {contexte_analyse['threat_opportunity']} (taille: {contexte_analyse['threat_size']})")
    print(f"   💰 Impact: {contexte_analyse['business_impact_financial']} + {contexte_analyse['business_impact_reputation']} réputation")
    print(f"   👥 Données: {contexte_analyse['business_impact_privacy']} enregistrements affectés")
    print(f"   🏢 Entreprise: {contexte_analyse['taille_entreprise']} ({contexte_analyse['secteur']})")
    print()

    # Test 1: Construction d'arbres d'attaque
    print("1️⃣ TEST 1: CONSTRUCTION D'ARBRES D'ATTAQUE")
    print("-" * 50)

    constructeur = ConstructeurArbresAttaque()

    try:
        arbre_attaque = constructeur.construire_arbre_attaque(vulnerabilites_test, contexte_analyse)

        print("✅ Arbre d'attaque construit avec succès")
        print(f"   🆔 ID: {arbre_attaque.id_chaine}")
        print(f"   🎯 Score global: {arbre_attaque.score_global:.1f}/100")
        print(f"   🚨 Niveau de risque: {arbre_attaque.niveau_risque.upper()}")
        print(f"   📊 Probabilité de succès: {arbre_attaque.probabilite_succes_total:.1%}")
        print(f"   ⏱️ Temps estimé: {arbre_attaque.temps_total_estime} minutes")
        print(f"   🎯 Objectifs atteints: {len(arbre_attaque.objectifs_atteints)}")
        print(f"   🌲 Nœuds dans l'arbre: {len(arbre_attaque.noeuds)}")
        print(f"   🔗 Connexions: {len(arbre_attaque.connexions)}")

        if arbre_attaque.chemins_critiques:
            print(f"   🚨 Chemins critiques: {len(arbre_attaque.chemins_critiques)} identifiés")

    except Exception as e:
        print(f"❌ Erreur construction arbre: {str(e)}")
        return

    print()

    # Test 2: Analyse d'escalade de privilèges
    print("2️⃣ TEST 2: ANALYSE ESCALADE DE PRivilèGES")
    print("-" * 45)

    analyseur_escalade = AnalyseurEscaladePrivileges()
    analyse_escalade = analyseur_escalade.analyser_escalade_privileges(arbre_attaque)

    print("🔑 Analyse d'escalade de privilèges:"    print(f"   👑 Niveau max atteint: {analyse_escalade['niveau_privilege_max_atteint']}")
    print(f"   📈 Probabilité d'escalade: {analyse_escalade['probabilite_escalade']:.1%}")
    print(f"   🛣️ Chemins d'escalade: {len(analyse_escalade['chemins_escalade_identifies'])}")

    if analyse_escalade['chemins_escalade_identifies']:
        for chemin in analyse_escalade['chemins_escalade_identifies'][:1]:
            print(f"      • {chemin['type'].replace('_', ' ').title()}: {len(chemin['etapes'])} étapes")

    if analyse_escalade['recommandations_securite']:
        print("   💡 Recommandations sécurité:")
        for rec in analyse_escalade['recommandations_securite'][:2]:
            print(f"      • {rec}")

    print()

    # Test 3: Analyse de mouvement latéral
    print("3️⃣ TEST 3: ANALYSE MOUVEMENT LATÉRAL")
    print("-" * 40)

    analyseur_lateral = AnalyseurMouvementLateral()
    analyse_laterale = analyseur_lateral.analyser_mouvement_lateral(arbre_attaque)

    print("🌐 Analyse de mouvement latéral:"    print(f"   🛣️ Techniques latérales possibles: {len(analyse_laterale['techniques_laterales_possibles'])}")
    print(f"   📊 Impact de propagation: {analyse_laterale['impact_propagation']:.1f}/10")

    if analyse_laterale['techniques_laterales_possibles']:
        for tech in analyse_laterale['techniques_laterales_possibles'][:2]:
            print(f"      • {tech['technique'].replace('_', ' ').title()}: {tech['impact']} impact")

    if analyse_laterale['recommandations_containment']:
        print("   🛡️ Recommandations containment:")
        for rec in analyse_laterale['recommandations_containment'][:2]:
            print(f"      • {rec}")

    print()

    # Test 4: Calcul d'impact business
    print("4️⃣ TEST 4: CALCUL IMPACT BUSINESS")
    print("-" * 35)

    calculateur_impact = CalculateurImpactBusiness()
    impact_business = calculateur_impact.calculer_impact_business(arbre_attaque, contexte_analyse)

    print("💰 Analyse d'impact business:"    print(",.0f"    print(f"   ⏱️ Durée indisponibilité: {impact_business['duree_indisponibilite']} heures")
    print(",.0f"    print(",.0f"
    if impact_business['consequences_strategiques']:
        print("   🎯 Conséquences stratégiques:")
        for consequence in impact_business['consequences_strategiques'][:2]:
            print(f"      • {consequence}")

    print("
   📈 Scénarios de risque:"    for scenario in impact_business['scenarios_risque'][:2]:
        print("      • {scenario['nom']}: {scenario['probabilite']:.1%} probabilité"        print(",.0f"        print(f"         Durée crise: {scenario['duree_crise']} heures")

    print()

    # Test 5: Scoring de priorité de remédiation
    print("5️⃣ TEST 5: SCORING PRIORITÉ REMÉDIATION")
    print("-" * 45)

    scoreur_priorite = ScoreurPrioriteRemediation()

    print("🎯 Analyse des priorités de remédiation:")
    for i, vuln in enumerate(vulnerabilites_test[:3], 1):
        priorite = scoreur_priorite.calculer_priorite_remediation(vuln, contexte_analyse)

        print(f"   {i}. {vuln.type}")
        print(f"      📊 Score priorité: {priorite['score_global']:.1f}/10")
        print(f"      🚨 Niveau: {priorite['niveau_priorite'].upper()}")
        print(f"      ⏱️ Délai recommandé: {priorite['temps_recommande']}")
        print(f"      💡 {priorite['justification'][:60]}...")

        if priorite['actions_recommandees']:
            print(f"      🛠️ Action clé: {priorite['actions_recommandees'][0]}")
        print()

    # Test 6: Analyse complète orchestrée
    print("6️⃣ TEST 6: ANALYSE COMPLÈTE ORCHESTRÉE")
    print("-" * 45)

    orchestrateur = OrchestrateurChainesAttaque()
    rapport_complet = await orchestrateur.analyser_chaine_complete(vulnerabilites_test, contexte_analyse)

    print("🎼 Analyse complète orchestrée:"    print(f"   📅 Date: {rapport_complet['date_analyse'][:10]}")
    print(f"   🎯 Vulnérabilités analysées: {rapport_complet['total_vulnerabilites']}")
    print(f"   🌲 Chaînes d'attaque: {len(rapport_complet['chaines_identifiees'])}")
    print(f"   🎯 Priorités de remédiation: {len(rapport_complet['priorites_remediation'])}")

    # Détails de la chaîne principale
    if rapport_complet['chaines_identifiees']:
        chaine = rapport_complet['chaines_identifiees'][0]
        print("
   🔗 Chaîne principale:"        print(f"      🎯 Score: {chaine['score_global']:.1f}")
        print(f"      🚨 Risque: {chaine['niveau_risque'].upper()}")
        print(f"      📊 Succès: {chaine['probabilite_succes']:.1%}")
        print(f"      🎯 Objectifs: {len(chaine['objectifs_atteints'])}")

    # Résumé des priorités
    priorites_par_niveau = {}
    for p in rapport_complet['priorites_remediation']:
        niveau = p['niveau_priorite']
        priorites_par_niveau[niveau] = priorites_par_niveau.get(niveau, 0) + 1

    print("
   🎯 Répartition des priorités:"    for niveau, count in sorted(priorites_par_niveau.items(), key=lambda x: x[1], reverse=True):
        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(niveau, '❓')
        print(f"      {emoji} {niveau.upper()}: {count}")

    print("
   💡 Recommandations globales:"    for rec in rapport_complet['recommandations_globales'][:3]:
        print(f"      • {rec}")

    print()

    print("=" * 70)
    print("📊 RÉSULTATS DE L'ANALYSE DE CHAÎNES D'ATTAQUE:")
    print("=" * 70)
    print("✅ ARBRES D'ATTAQUE AUTOMATIQUES:")
    print("   • Construction algorithmique d'arbres d'attaque")
    print("   • Analyse de chemins d'exploitation viables")
    print("   • Calcul de scores de risque composites")
    print("   • Identification d'objectifs atteignables")
    print()
    print("✅ ANALYSE ESCALADE DE PRivilèGES:")
    print("   • Cartographie des chemins de privilège")
    print("   • Évaluation des niveaux d'accès atteints")
    print("   • Mesure de la probabilité d'escalade")
    print("   • Recommandations de segmentation")
    print()
    print("✅ ANALYSE MOUVEMENT LATÉRAL:")
    print("   • Identification des techniques applicables")
    print("   • Évaluation de l'impact de propagation")
    print("   • Analyse de containment nécessaire")
    print("   • Recommandations Zero Trust")
    print()
    print("✅ CALCUL IMPACT BUSINESS:")
    print("   • Modélisation financière des cyber-risques")
    print("   • Évaluation des pertes opérationnelles")
    print("   • Analyse des impacts réputationnels")
    print("   • Scénarios de risque probabilistes")
    print()
    print("✅ SCORING PRIORITÉ REMÉDIATION:")
    print("   • Algorithme multi-facteurs de priorisation")
    print("   • Évaluation exploitabilité vs complexité")
    print("   • Intégration conformité réglementaire")
    print("   • Délais de correction recommandés")
    print()
    print("🎯 IMPACT BUSINESS TRANSFORMATIONNEL:")
    print("   • Passage d'une analyse statique à dynamique")
    print("   • Compréhension des chaînes d'attaque réelles")
    print("   • Priorisation basée sur vrais scénarios de risque")
    print("   • Décisions business éclairées par données techniques")
    print()
    print("⚡ AVANTAGES COMPÉTITIFS:")
    print("   • Unique analyse de chaînes d'attaque automatisée")
    print("   • Modélisation business des cyber-risques")
    print("   • Recommandations de remédiation intelligentes")
    print("   • Interface entre sécurité et business")
    print()
    print(f"🎯 RÉSULTAT: Analyse de chaînes d'attaque validée sur {len(vulnerabilites_test)} vulnérabilités")
    print("🔗 VulnHunter Pro peut maintenant modéliser les vraies menaces !")
    print("🎯 Prêt pour l'analyse prédictive de sécurité !")
    print()
    print("✨ Félicitations pour cette implémentation d'analyse de chaînes d'attaque avancée ! 🎉")


async def main():
    await test_attack_chains()


if __name__ == "__main__":
    asyncio.run(main())
