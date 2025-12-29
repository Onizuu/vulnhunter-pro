#!/usr/bin/env python3
"""
Test rapide du système distribué
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.distributed_scanner import OrchestrateurDistribue
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")


async def test_rapide():
    """Test rapide du système distribué"""
    print("🚀 TEST RAPIDE SYSTÈME DISTRIBUÉ")
    print("=" * 50)

    orchestrateur = OrchestrateurDistribue(max_workers_threads=5, max_workers_process=1)

    # Ajouter un proxy
    orchestrateur.ajouter_proxy("http://proxy.example.com:8080")

    urls = [
        "https://httpbin.org/get",
        "https://httpbin.org/uuid",
        "https://httpbin.org/json"
    ]

    config = {'priorite': 1, 'timeout': 10}

    print(f"📋 Test avec {len(urls)} URLs...")

    resultats = await orchestrateur.scanner_distribue(urls, config)

    print("\n✅ TEST TERMINÉ")
    print(f"📊 Scans: {resultats['scans_total']}")
    print(f"✅ Réussis: {resultats['scans_reussis']}")
    print(f"📈 Succès: {resultats['taux_succes']:.1%}")

    # Statistiques
    stats = orchestrateur.obtenir_statistiques_globales()
    print("\n🏭 Workers:")
    print(f"   Load balancer: {len(stats['load_balancer']['workers'])} workers")
    print(f"   Rate limiter: {stats['rate_limiter']['requetes_actives']} requêtes")
    print(f"   Proxy rotator: {stats['proxy_rotator']['total_proxies']} proxies")

    print("\n✅ Système distribué opérationnel !")


if __name__ == "__main__":
    asyncio.run(test_rapide())
