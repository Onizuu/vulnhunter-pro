#!/usr/bin/env python3
"""
Test simple du générateur de payloads IA avancé
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules.intelligence.ai_payload_generator import GenerateurPayloadsIA
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")


async def test_simple():
    """Test simple du générateur IA"""
    print("🎯 TEST SIMPLE GÉNÉRATEUR PAYLOADS IA")
    print("=" * 50)

    generator = GenerateurPayloadsIA()

    # Test génération SQLi bypass Cloudflare
    contexte = {
        'technology': 'php',
        'waf': 'cloudflare'
    }

    payloads = await generator.generer_payloads_avances(
        'sql_injection',
        contexte,
        nombre_payloads=3
    )

    print(f"✅ {len(payloads)} payloads générés")

    for i, p in enumerate(payloads, 1):
        print(f"{i}. {p['payload'][:50]}... (score: {p['score_confiance']:.2f})")

    # Test techniques bypass
    test_payload = "UNION SELECT 1,2,3--"
    variations = generator._appliquer_technique_bypass(test_payload, 'case_variation')
    print(f"\n🔄 Variations pour case_variation: {len(variations)}")

    # Test rapport
    rapport = generator.generer_rapport_payloads(payloads)
    print(f"📊 Rapport: {rapport['total_payloads']} payloads, moyenne {rapport['moyenne_confiance']:.2f}")

    print("\n✅ Test terminé avec succès!")


if __name__ == "__main__":
    asyncio.run(test_simple())
