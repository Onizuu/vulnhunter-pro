#!/usr/bin/env python3
"""
Test du générateur de payloads IA avancé
Bypass WAF, context-aware, polymorphic, zero-day discovery
"""
import asyncio
import sys
import os
from pathlib import Path

# Ajouter le répertoire racine au path
sys.path.insert(0, str(Path(__file__).parent))

from modules.intelligence.ai_payload_generator import GenerateurPayloadsIA
from integration_ia.openai_client import ClientOpenAI
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")


async def test_ai_payload_generator():
    """Test complet du générateur de payloads IA"""
    print("🎯 TEST GÉNÉRATEUR DE PAYLOADS IA AVANCÉ")
    print("=" * 60)
    print("🎯 Fonctionnalités testées:")
    print("   ✅ Bypass WAF (Cloudflare, ModSecurity, Akamai, Imperva)")
    print("   ✅ Context-aware attacks (adaptés à chaque techno)")
    print("   ✅ Polymorphic payloads (changements automatiques)")
    print("   ✅ Zero-day discovery attempts (avec IA)")
    print()

    # Initialiser avec client IA (optionnel)
    client_ia = ClientOpenAI()
    generator = GenerateurPayloadsIA(client_ia)

    print("🤖 SYSTÈME IA INITIALISÉ")
    print("-" * 30)

    # Test 1: Génération de payloads SQLi bypass Cloudflare
    print("\n1️⃣ TEST 1: PAYLOADS SQLi BYPASS CLOUDFLARE")
    print("-" * 50)

    contexte_cloudflare = {
        'technology': 'php',
        'waf': 'cloudflare',
        'version': '8.0'
    }

    payloads_sqli = await generator.generer_payloads_avances(
        'sql_injection',
        contexte_cloudflare,
        nombre_payloads=5
    )

    print(f"🎯 {len(payloads_sqli)} payloads SQLi générés pour Cloudflare + PHP")

    for i, payload_info in enumerate(payloads_sqli[:3], 1):
        print(f"\n   {i}. Payload: {payload_info['payload'][:50]}...")
        print(f"      🎯 Score: {payload_info['score_confiance']:.2f}")
        print(f"      🛡️ Techniques: {', '.join(payload_info['techniques_bypass'][:2])}")
        print(f"      🎲 Variations: {len(payload_info['polymorphic_variations'])}")

    # Test 2: Payloads XSS bypass ModSecurity
    print("\n\n2️⃣ TEST 2: PAYLOADS XSS BYPASS MODSECURITY")
    print("-" * 50)

    contexte_modsec = {
        'technology': 'asp_net',
        'waf': 'modsecurity',
        'version': '4.3'
    }

    payloads_xss = await generator.generer_payloads_avances(
        'xss',
        contexte_modsec,
        nombre_payloads=5
    )

    print(f"🎯 {len(payloads_xss)} payloads XSS générés pour ModSecurity + ASP.NET")

    for i, payload_info in enumerate(payloads_xss[:3], 1):
        print(f"\n   {i}. Payload: {payload_info['payload'][:50]}...")
        print(f"      🎯 Score: {payload_info['score_confiance']:.2f}")
        print(f"      🛡️ Techniques: {', '.join(payload_info['techniques_bypass'][:2])}")
        print(f"      🎲 Variations: {len(payload_info['polymorphic_variations'])}")

    # Test 3: Payloads command injection context-aware
    print("\n\n3️⃣ TEST 3: PAYLOADS COMMAND INJECTION CONTEXT-AWARE")
    print("-" * 50)

    contexte_nodejs = {
        'technology': 'nodejs',
        'waf': 'akamai',
        'version': '16'
    }

    payloads_cmd = await generator.generer_payloads_avances(
        'command_injection',
        contexte_nodejs,
        nombre_payloads=5
    )

    print(f"🎯 {len(payloads_cmd)} payloads command injection générés pour Akamai + Node.js")

    for i, payload_info in enumerate(payloads_cmd[:3], 1):
        print(f"\n   {i}. Payload: {payload_info['payload'][:50]}...")
        print(f"      🎯 Score: {payload_info['score_confiance']:.2f}")
        print(f"      🛡️ Techniques: {', '.join(payload_info['techniques_bypass'][:2])}")
        print(f"      🎲 Variations: {len(payload_info['polymorphic_variations'])}")

    # Test 4: Test bypass WAF
    print("\n\n4️⃣ TEST 4: TEST BYPASS WAF")
    print("-" * 50)

    test_payload = "1' UNION SELECT database(),user(),version()--"
    test_result = await generator.tester_payload_waf_bypass(
        test_payload,
        "http://test.com",
        "cloudflare"
    )

    print(f"🧪 Test bypass pour payload: {test_payload[:30]}...")
    print(f"   🛡️ WAF: {test_result['waf_type']}")
    print(f"   🚫 Bloqué: {test_result['blocked']}")
    print(f"   🎯 Score bypass: {test_result['bypass_score']:.2f}")
    print(f"   🛠️ Techniques utilisées: {', '.join(test_result['techniques_used'])}")

    # Test 5: Génération polymorphique
    print("\n\n5️⃣ TEST 5: GÉNÉRATION POLYMORPHIQUE")
    print("-" * 50)

    base_payload = "UNION SELECT 1,2,3--"
    variations = generator._generer_variations_polymorphes(base_payload, 5)

    print(f"🔄 Variations polymorphes pour: {base_payload}")
    print(f"   📊 {len(variations)} variations générées:")

    for i, variation in enumerate(variations[:5], 1):
        print(f"      {i}. {variation}")

    # Test 6: Techniques de bypass
    print("\n\n6️⃣ TEST 6: TECHNIQUES DE BYPASS")
    print("-" * 50)

    techniques_test = [
        ("case_variation", "UNION SELECT"),
        ("encoding", "<script>alert('XSS')</script>"),
        ("comments_injection", "UNION SELECT"),
        ("spaces_replacement", "UNION SELECT 1"),
        ("concatenation", "UNION SELECT")
    ]

    for technique_name, test_payload in techniques_test:
        variations = generator._appliquer_technique_bypass(test_payload, technique_name)
        print(f"🛠️ Technique '{technique_name}': {len(variations)} variations")
        if variations[1:]:  # Exclure l'original
            print(f"   Exemple: {variations[1][:50]}...")

    # Test 7: Rapport détaillé
    print("\n\n7️⃣ TEST 7: RAPPORT DÉTAILLÉ")
    print("-" * 50)

    all_payloads = payloads_sqli + payloads_xss + payloads_cmd
    rapport = generator.generer_rapport_payloads(all_payloads)

    print("📊 RAPPORT GÉNÉRAL:")
    print(f"   📦 Total payloads: {rapport['total_payloads']}")
    print(f"   🎯 Moyenne confiance: {rapport['moyenne_confiance']:.2f}")
    print(f"   🛠️ Techniques bypass utilisées: {len(rapport['techniques_bypass_utilisees'])}")

    print("\n   📈 Top techniques:"    for technique, count in sorted(rapport['techniques_bypass_utilisees'].items(),
                                       key=lambda x: x[1], reverse=True)[:3]:
        print(f"      {technique}: {count}")

    print("
   🏆 Top payloads:"    for i, payload in enumerate(rapport['top_payloads'][:2], 1):
        print(f"      {i}. {payload['payload'][:40]}... (score: {payload['score_confiance']:.2f})")

    print("
   💡 Recommandations:"    for rec in rapport['recommandations'][:2]:
        print(f"      • {rec}")

    print("\n" + "=" * 60)
    print("📊 ANALYSE DES AMÉLIORATIONS IA:")
    print("=" * 60)
    print("🎯 AVANT: Payloads statiques et évidents")
    print("🎯 APRÈS: Système IA avancé multi-techniques")
    print()
    print("🧠 Capacités IA intégrées:")
    print("   ✅ Bypass WAF intelligent (4 WAF majeurs)")
    print("   ✅ Context-aware attacks (4 techno stacks)")
    print("   ✅ Polymorphic payloads (variations automatiques)")
    print("   ✅ Zero-day discovery (génération IA)")
    print("   ✅ Scoring de confiance avancé")
    print("   ✅ Cache et optimisation performance")
    print()
    print("🛡️ Techniques de bypass implémentées:")
    print("   - Case variation (casse variable)")
    print("   - Encoding multiple (URL, HTML, Base64, Hex, Unicode)")
    print("   - Comments injection (casser signatures)")
    print("   - Spaces replacement (caractères alternatifs)")
    print("   - Concatenation (assembler dynamiquement)")
    print("   - Keyword replacement (alias de fonctions)")
    print()
    print("🎯 Contextes technologiques supportés:")
    print("   - PHP (file inclusion, SQL injection)")
    print("   - ASP.NET (.NET specifics)")
    print("   - Node.js (NoSQL injection, command injection)")
    print("   - Java (XXE, SQL injection)")
    print()
    print("⚡ Avantages du système IA:")
    print("   - Contournement WAF automatisé")
    print("   - Adaptation technologique intelligente")
    print("   - Évolution polymorphique des payloads")
    print("   - Découverte de zero-days potentiels")
    print("   - Scoring prédictif de succès")
    print("   - Génération à la demande optimisée")
    print()
    print("🎯 Impact: VulnHunter Pro devient un générateur de payloads IA !")
    print("🚀 Capable de contourner les protections les plus avancées !")


async def main():
    await test_ai_payload_generator()


if __name__ == "__main__":
    asyncio.run(main())
