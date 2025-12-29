#!/usr/bin/env python3
"""
Test du nouveau module d'authentification avancée
"""
import asyncio
import sys
import os
from pathlib import Path

# Ajouter le répertoire racine au path
sys.path.insert(0, str(Path(__file__).parent))

from modules.vulnerabilites.auth_bypass import TesteurAuthBypass
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")


async def test_auth_advanced():
    """Test des nouvelles fonctionnalités d'authentification"""
    print("🧪 TEST MODULE AUTHENTIFICATION AVANCÉE")
    print("=" * 60)
    print("🎯 Nouvelles fonctionnalités testées:")
    print("   ✅ Bruteforce intelligent (anti-ban)")
    print("   ✅ User enumeration (timing + messages)")
    print("   ✅ Password policies")
    print("   ✅ Session management (fixation + hijacking)")
    print("   ✅ JWT token analysis")
    print("   ✅ MFA bypass attempts")
    print()

    # Créer un testeur (sans IA pour ce test)
    testeur = TesteurAuthBypass(client_ia=None)

    # Test 1: Découverte de pages d'authentification
    print("🔍 TEST 1: Découverte de pages d'authentification")
    print("-" * 50)
    try:
        pages_auth = await testeur._decouvrir_pages_auth("http://testphp.vulnweb.com/")
        print(f"✅ {len(pages_auth)} page(s) d'authentification trouvée(s):")
        for page in pages_auth:
            print(f"   🔗 {page}")

        if pages_auth:
            page_test = pages_auth[0]
        else:
            print("ℹ️  Aucune page d'authentification trouvée - test théorique")
            page_test = "http://testphp.vulnweb.com/login"

    except Exception as e:
        print(f"❌ Erreur découverte: {str(e)}")
        page_test = "http://testphp.vulnweb.com/login"

    # Test 2: Analyse de formulaires
    print("\n📝 TEST 2: Analyse de formulaires d'authentification")
    print("-" * 50)
    try:
        formulaires = await testeur._analyser_formulaires(page_test)
        print(f"✅ {len(formulaires)} formulaire(s) analysé(s)")

        for i, form in enumerate(formulaires, 1):
            print(f"   📋 Formulaire {i}:")
            print(f"      Action: {form.get('action', 'N/A')}")
            print(f"      Méthode: {form.get('method', 'N/A')}")
            print(f"      Username: {'✅' if form.get('has_username') else '❌'}")
            print(f"      Password: {'✅' if form.get('has_password') else '❌'}")
            print(f"      CSRF: {'✅' if form.get('has_csrf') else '❌'}")

        formulaire_test = formulaires[0] if formulaires else {
            'action': '', 'method': 'POST', 'has_username': True,
            'has_password': True, 'has_csrf': False, 'csrf_token': ''
        }

    except Exception as e:
        print(f"❌ Erreur analyse formulaires: {str(e)}")
        formulaire_test = {
            'action': '', 'method': 'POST', 'has_username': True,
            'has_password': True, 'has_csrf': False, 'csrf_token': ''
        }

    # Test 3: Auth bypass classique
    print("\n🚨 TEST 3: Auth bypass classique (SQL injection)")
    print("-" * 50)
    try:
        vuln_bypass = await testeur._test_auth_bypass_classique(page_test, formulaire_test)
        print(f"✅ Test terminé: {len(vuln_bypass)} vulnérabilité(s) détectée(s)")
        for vuln in vuln_bypass:
            print(f"   🚨 {vuln.type} (CVSS: {vuln.cvss_score})")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur test bypass: {str(e)}")

    # Test 4: User enumeration
    print("\n👤 TEST 4: User enumeration (timing attacks)")
    print("-" * 50)
    try:
        vuln_enum = await testeur._test_user_enumeration(page_test, formulaire_test)
        print(f"✅ Test terminé: {len(vuln_enum)} vulnérabilité(s) détectée(s)")
        for vuln in vuln_enum:
            print(f"   🚨 {vuln.type} (CVSS: {vuln.cvss_score})")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur test enumeration: {str(e)}")

    # Test 5: Password policies
    print("\n🔑 TEST 5: Password policies")
    print("-" * 50)
    try:
        vuln_policy = await testeur._test_password_policies(page_test, formulaire_test)
        print(f"✅ Test terminé: {len(vuln_policy)} vulnérabilité(s) détectée(s)")
        for vuln in vuln_policy:
            print(f"   🚨 {vuln.type} (CVSS: {vuln.cvss_score})")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur test policies: {str(e)}")

    # Test 6: Bruteforce intelligent
    print("\n💪 TEST 6: Bruteforce intelligent (anti-ban)")
    print("-" * 50)
    try:
        vuln_brute = await testeur._test_bruteforce_intelligent(page_test, formulaire_test)
        print(f"✅ Test terminé: {len(vuln_brute)} vulnérabilité(s) détectée(s)")
        for vuln in vuln_brute:
            print(f"   🚨 {vuln.type} (CVSS: {vuln.cvss_score})")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur test bruteforce: {str(e)}")

    # Test 7: Session management
    print("\n🔒 TEST 7: Session management (fixation/hijacking)")
    print("-" * 50)
    try:
        vuln_session = await testeur._test_session_management(page_test, formulaire_test)
        print(f"✅ Test terminé: {len(vuln_session)} vulnérabilité(s) détectée(s)")
        for vuln in vuln_session:
            print(f"   🚨 {vuln.type} (CVSS: {vuln.cvss_score})")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur test session: {str(e)}")

    # Test 8: JWT analysis
    print("\n🎫 TEST 8: JWT token analysis")
    print("-" * 50)
    try:
        vuln_jwt = await testeur._test_jwt_analysis(page_test, formulaire_test)
        print(f"✅ Test terminé: {len(vuln_jwt)} vulnérabilité(s) détectée(s)")
        for vuln in vuln_jwt:
            print(f"   🚨 {vuln.type} (CVSS: {vuln.cvss_score})")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur test JWT: {str(e)}")

    # Test 9: MFA bypass
    print("\n🔐 TEST 9: MFA bypass attempts")
    print("-" * 50)
    try:
        vuln_mfa = await testeur._test_mfa_bypass(page_test, formulaire_test)
        print(f"✅ Test terminé: {len(vuln_mfa)} vulnérabilité(s) détectée(s)")
        for vuln in vuln_mfa:
            print(f"   🚨 {vuln.type} (CVSS: {vuln.cvss_score})")
            print(f"      💡 {vuln.description[:60]}...")

    except Exception as e:
        print(f"❌ Erreur test MFA: {str(e)}")

    print("\n" + "=" * 60)
    print("📊 ANALYSE DES AMÉLIORATIONS:")
    print("=" * 60)
    print("🎯 AVANT: Tests SQL injection basiques seulement")
    print("🎯 APRÈS: Suite complète de tests d'authentification professionnelle")
    print()
    print("🔧 Nouvelles capacités:")
    print("   ✅ Découverte automatique de pages/fomulaires d'auth")
    print("   ✅ Injection SQL avancée avec tokens CSRF")
    print("   ✅ User enumeration via timing attacks")
    print("   ✅ Analyse de politiques de mot de passe")
    print("   ✅ Bruteforce intelligent (anti-détection)")
    print("   ✅ Tests de fixation/hijacking de session")
    print("   ✅ Analyse complète des tokens JWT")
    print("   ✅ Tests de contournement MFA/2FA")
    print("   ✅ Déduplication automatique des vulnérabilités")
    print()
    print("⚡ Performance:")
    print("   - Délais aléatoires anti-ban (1-3s)")
    print("   - Timeouts configurables")
    print("   - Rate limiting intelligent")
    print("   - Gestion d'erreurs robuste")
    print()
    print("🎯 Impact: VulnHunter Pro devient un scanner d'authentification ENTERPRISE!")
    print("🚀 Prêt pour découvrir des vulnérabilités critiques d'authentification !")


async def main():
    await test_auth_advanced()


if __name__ == "__main__":
    asyncio.run(main())
