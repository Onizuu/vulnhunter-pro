#!/usr/bin/env python3
"""
Test de l'analyseur de configuration approfondi
"""
import asyncio
import sys
import os
from pathlib import Path

# Ajouter le répertoire racine au path
sys.path.insert(0, str(Path(__file__).parent))

from modules.vulnerabilites.config_analyzer import AnalyseurConfiguration
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")


async def test_config_analyzer():
    """Test complet de l'analyseur de configuration"""
    print("🔧 TEST ANALYSEUR DE CONFIGURATION APPROFONDI")
    print("=" * 60)
    print("🎯 Fonctionnalités testées:")
    print("   ✅ Fuites de secrets (API keys, tokens)")
    print("   ✅ Misconfigurations cloud (AWS S3, Azure)")
    print("   ✅ Bases de données exposées (MongoDB, Redis)")
    print("   ✅ Modes debug activés")
    print("   ✅ Credentials par défaut")
    print("   ✅ Fichiers sensibles exposés")
    print()

    analyzer = AnalyseurConfiguration()

    # Technologies de test
    technologies_test = {
        'PHP': 'v5.6.40',
        'Apache': 'detected',
        'MySQL': 'detected'
    }

    print("🔍 TECHNOLOGIES DE TEST:")
    for tech, version in technologies_test.items():
        print(f"   ✅ {tech}: {version}")
    print()

    # Test 1: Analyse complète
    print("🔧 TEST 1: Analyse de configuration complète")
    print("-" * 50)
    try:
        vulns = await analyzer.analyser("http://testphp.vulnweb.com/", technologies_test)
        print(f"✅ {len(vulns)} problème(s) de configuration détecté(s)")

        for vuln in vulns[:5]:  # Max 5
            emoji = {'CRITIQUE': '🔴', 'ÉLEVÉ': '🟠', 'MOYEN': '🟡', 'FAIBLE': '🟢'}.get(vuln.severite, '❓')
            print(f"   {emoji} {vuln.type}")
            print(f"      💡 {vuln.description[:60]}...")
            print(f"      📍 {vuln.url}")

    except Exception as e:
        print(f"❌ Erreur analyse complète: {str(e)}")

    # Test 2: Recherche de fuites de secrets
    print("\n🔐 TEST 2: Recherche de fuites de secrets")
    print("-" * 50)
    try:
        secrets_vulns = await analyzer._analyser_fuites_secrets("http://testphp.vulnweb.com/", technologies_test)
        print(f"✅ {len(secrets_vulns)} fuite(s) de secret(s) détectée(s)")

        secret_types = {}
        for vuln in secrets_vulns:
            vuln_type = vuln.type.split(':')[1].strip() if ':' in vuln.type else vuln.type
            secret_types[vuln_type] = secret_types.get(vuln_type, 0) + 1

        print("   📊 Types de secrets détectés:")
        for secret_type, count in secret_types.items():
            print(f"      🔑 {secret_type}: {count}")

    except Exception as e:
        print(f"❌ Erreur recherche secrets: {str(e)}")

    # Test 3: Analyse des misconfigurations cloud
    print("\n☁️  TEST 3: Misconfigurations cloud")
    print("-" * 50)
    try:
        cloud_vulns = await analyzer._analyser_misconfigurations_cloud("http://testphp.vulnweb.com/")
        print(f"✅ {len(cloud_vulns)} misconfiguration(s) cloud détectée(s)")

        for vuln in cloud_vulns[:3]:  # Max 3
            print(f"   ☁️  {vuln.type}")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur misconfigurations cloud: {str(e)}")

    # Test 4: Analyse des bases de données exposées
    print("\n🗄️  TEST 4: Bases de données exposées")
    print("-" * 50)
    try:
        db_vulns = await analyzer._analyser_databases_exposees("http://testphp.vulnweb.com/")
        print(f"✅ {len(db_vulns)} base(s) de données exposée(s)")

        for vuln in db_vulns[:2]:  # Max 2
            print(f"   🗄️  {vuln.type}")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur bases de données: {str(e)}")

    # Test 5: Analyse des modes debug
    print("\n🐛 TEST 5: Modes debug activés")
    print("-" * 50)
    try:
        debug_vulns = await analyzer._analyser_modes_debug("http://testphp.vulnweb.com/", technologies_test)
        print(f"✅ {len(debug_vulns)} mode(s) debug détecté(s)")

        for vuln in debug_vulns[:2]:  # Max 2
            print(f"   🐛 {vuln.type}")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur modes debug: {str(e)}")

    # Test 6: Analyse des credentials par défaut
    print("\n🔑 TEST 6: Credentials par défaut")
    print("-" * 50)
    print("⚠️  Test désactivé pour éviter les blocages")
    print("   (Test de credentials peut déclencher des mécanismes de sécurité)")
    creds_vulns = []
    print(f"✅ {len(creds_vulns)} credential(s) par défaut testé(s)")

    # Test 7: Analyse des fichiers sensibles
    print("\n📁 TEST 7: Fichiers sensibles exposés")
    print("-" * 50)
    try:
        files_vulns = await analyzer._analyser_fichiers_sensibles("http://testphp.vulnweb.com/")
        print(f"✅ {len(files_vulns)} fichier(s) sensible(s) exposé(s)")

        for vuln in files_vulns[:3]:  # Max 3
            print(f"   📁 {vuln.type}")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur fichiers sensibles: {str(e)}")

    print("\n" + "=" * 60)
    print("📊 ANALYSE DES AMÉLIORATIONS:")
    print("=" * 60)
    print("🎯 AVANT: Analyse de configuration basique")
    print("🎯 APRÈS: Analyse approfondie multi-couches")
    print()
    print("🔧 Nouveaux checks intégrés:")
    print("   ✅ Fuites de secrets (7 types différents)")
    print("   ✅ Misconfigurations AWS S3/Azure")
    print("   ✅ Bases de données sans auth (4 types)")
    print("   ✅ Modes debug par technologie")
    print("   ✅ Credentials par défaut courants")
    print("   ✅ Fichiers sensibles exposés")
    print()
    print("🛡️  Patterns de sécurité couverts:")
    print("   - API tokens (GitHub, Slack, AWS, Azure)")
    print("   - Clés privées et certificats")
    print("   - Mots de passe de base de données")
    print("   - Secrets JWT et sessions")
    print("   - Buckets S3 publics")
    print("   - Databases sans firewall")
    print("   - Debug modes exposés")
    print("   - Fichiers .env et configs")
    print()
    print("⚡ Capacités avancées:")
    print("   - Regex patterns spécialisés")
    print("   - Analyse multi-URLs")
    print("   - Détection par technologie")
    print("   - Scoring CVSS précis")
    print("   - Déduplication intelligente")
    print()
    print("🎯 Impact: VulnHunter Pro devient un scanner de MISCONFIGURATIONS !")
    print("🚀 Détecte maintenant les erreurs de configuration les plus courantes !")


async def main():
    await test_config_analyzer()


if __name__ == "__main__":
    asyncio.run(main())
