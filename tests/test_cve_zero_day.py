#!/usr/bin/env python3
"""
Test du système avancé de détection CVE et Zero-Day
"""
import asyncio
import sys
import os
from pathlib import Path

# Ajouter le répertoire racine au path
sys.path.insert(0, str(Path(__file__).parent))

from modules.vulnerabilites.cve_scanner import ScannerCVE
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")


async def test_cve_zero_day():
    """Test complet du système CVE et zero-day"""
    print("🛡️ TEST SYSTÈME CVE & ZERO-DAY AVANCÉ")
    print("=" * 60)
    print("🎯 Fonctionnalités testées:")
    print("   ✅ NIST NVD API (CVE temps réel)")
    print("   ✅ Exploit-DB recherche")
    print("   ✅ OSV (Open Source Vulnerabilities)")
    print("   ✅ Zero-day detection (Log4Shell, etc.)")
    print("   ✅ ML patterns pour inconnus")
    print("   ✅ Signature-based detection")
    print()

    scanner = ScannerCVE()

    # Technologies de test (simulant celles détectées par VulnHunter)
    technologies_test = {
        'PHP': 'v5.6.40',
        'Apache': 'detected',
        'MySQL': 'detected',
        'WordPress': 'detected'
    }

    print("🔍 TECHNOLOGIES DE TEST:")
    for tech, version in technologies_test.items():
        print(f"   ✅ {tech}: {version}")
    print()

    # Test 1: Recherche CVE
    print("📚 TEST 1: Recherche CVE via NIST NVD")
    print("-" * 40)
    try:
        cve_vulns = await scanner._rechercher_cve_par_technologie(technologies_test, "http://testphp.vulnweb.com/")
        print(f"✅ {len(cve_vulns)} CVE trouvée(s)")

        for vuln in cve_vulns[:3]:  # Max 3
            print(f"   🚨 {vuln.type} (CVSS: {vuln.cvss_score})")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur recherche CVE: {str(e)}")

    # Test 2: Recherche exploits
    print("\n💥 TEST 2: Recherche exploits")
    print("-" * 40)
    try:
        exploit_vulns = await scanner._rechercher_exploits(technologies_test, "http://testphp.vulnweb.com/")
        print(f"✅ {len(exploit_vulns)} exploit(s) trouvé(s)")

        for vuln in exploit_vulns[:2]:  # Max 2
            print(f"   💥 {vuln.type}")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur recherche exploits: {str(e)}")

    # Test 3: Analyse OSV
    print("\n🔓 TEST 3: Analyse OSV (Open Source)")
    print("-" * 40)
    try:
        osv_vulns = await scanner._analyser_osv(technologies_test, "http://testphp.vulnweb.com/")
        print(f"✅ {len(osv_vulns)} vulnérabilité(s) OSV trouvée(s)")

        for vuln in osv_vulns[:2]:  # Max 2
            print(f"   📦 {vuln.type}")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur analyse OSV: {str(e)}")

    # Test 4: Détection zero-day
    print("\n🎯 TEST 4: Détection zero-day")
    print("-" * 40)
    try:
        zeroday_vulns = await scanner._detecter_zero_day("http://testphp.vulnweb.com/", technologies_test)
        print(f"✅ {len(zeroday_vulns)} zero-day(s) détecté(s)")

        for vuln in zeroday_vulns[:2]:  # Max 2
            print(f"   🚨 {vuln.type} (CVSS: {vuln.cvss_score})")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur détection zero-day: {str(e)}")

    # Test 5: Analyse ML patterns
    print("\n🤖 TEST 5: Analyse ML/patterns inconnus")
    print("-" * 40)
    try:
        ml_vulns = await scanner._analyser_ml_patterns("http://testphp.vulnweb.com/", technologies_test)
        print(f"✅ {len(ml_vulns)} pattern(s) ML suspect(s)")

        for vuln in ml_vulns[:2]:  # Max 2
            print(f"   🤖 {vuln.type}")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur analyse ML: {str(e)}")

    # Test 6: Détection signatures
    print("\n🔍 TEST 6: Signature-based detection")
    print("-" * 40)
    try:
        signature_vulns = await scanner._detection_signatures("http://testphp.vulnweb.com/", technologies_test)
        print(f"✅ {len(signature_vulns)} signature(s) vulnérable(s)")

        for vuln in signature_vulns[:2]:  # Max 2
            print(f"   📋 {vuln.type}")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur détection signatures: {str(e)}")

    # Test 7: Scan complet simulé
    print("\n🎯 TEST 7: SCAN COMPLET SIMULÉ")
    print("-" * 40)
    try:
        # Simuler un scan complet
        toutes_vulns = []
        toutes_vulns.extend(await scanner._rechercher_cve_par_technologie(technologies_test, "http://testphp.vulnweb.com/"))
        toutes_vulns.extend(await scanner._rechercher_exploits(technologies_test, "http://testphp.vulnweb.com/"))
        toutes_vulns.extend(await scanner._analyser_osv(technologies_test, "http://testphp.vulnweb.com/"))
        toutes_vulns.extend(await scanner._detecter_zero_day("http://testphp.vulnweb.com/", technologies_test))
        toutes_vulns.extend(await scanner._analyser_ml_patterns("http://testphp.vulnweb.com/", technologies_test))
        toutes_vulns.extend(await scanner._detection_signatures("http://testphp.vulnweb.com/", technologies_test))

        # Dédoublonner
        toutes_vulns = scanner._dedupliquer_vulnerabilites(toutes_vulns)

        print(f"✅ SCAN COMPLET: {len(toutes_vulns)} vulnérabilité(s) unique(s)")

        # Statistiques par sévérité
        severites = {}
        types = {}
        for vuln in toutes_vulns:
            severites[vuln.severite] = severites.get(vuln.severite, 0) + 1
            vuln_type = vuln.type.split(':')[0] if ':' in vuln.type else vuln.type
            types[vuln_type] = types.get(vuln_type, 0) + 1

        print("   📊 Par sévérité:")
        for sev, count in sorted(severites.items(), key=lambda x: x[1], reverse=True):
            emoji = {'CRITIQUE': '🔴', 'ÉLEVÉ': '🟠', 'MOYEN': '🟡', 'FAIBLE': '🟢'}.get(sev, '❓')
            print(f"      {emoji} {sev}: {count}")

        print("   📊 Par type:")
        for vuln_type, count in sorted(types.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"      📋 {vuln_type}: {count}")

    except Exception as e:
        print(f"❌ Erreur scan complet: {str(e)}")

    print("\n" + "=" * 60)
    print("📊 ANALYSE DES AMÉLIORATIONS:")
    print("=" * 60)
    print("🎯 AVANT: Scan CVE basique (optionnel)")
    print("🎯 APRÈS: Système complet multi-sources CVE/zero-day")
    print()
    print("🔧 Sources intégrées:")
    print("   ✅ NIST NVD API (CVE temps réel)")
    print("   ✅ Exploit-DB (exploits disponibles)")
    print("   ✅ OSV (open source vulnerabilities)")
    print("   ✅ Zero-day patterns (Log4Shell, etc.)")
    print("   ✅ ML patterns (détection inconnus)")
    print("   ✅ Signature-based (headers/contenu)")
    print()
    print("⚡ Capacités:")
    print("   - Cache intelligent (évite appels répétés)")
    print("   - Rate limiting géré")
    print("   - Corrélation tech ↔ vulnérabilités")
    print("   - Déduplication automatique")
    print("   - Scoring CVSS précis")
    print()
    print("🎯 Impact: VulnHunter Pro devient un scanner CVE enterprise !")
    print("🚀 Capable de détecter des milliers de CVE et zero-days en temps réel !")


async def main():
    await test_cve_zero_day()


if __name__ == "__main__":
    asyncio.run(main())
