#!/usr/bin/env python3
"""
Test du scanner de ports avancé
"""
import asyncio
import sys
import os
from pathlib import Path

# Ajouter le répertoire racine au path
sys.path.insert(0, str(Path(__file__).parent))

from modules.reconnaissance.port_scanner import ScannerPorts
from loguru import logger

logger.remove()
logger.add(lambda msg: print(msg, end=''), colorize=True, format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | <level>{message}</level>")


async def test_port_scanner():
    """Test du scanner de ports avancé"""
    print("🧪 TEST SCANNER DE PORTS AVANCÉ")
    print("=" * 50)
    print("🎯 Test sur différents niveaux d'intensité:")
    print("   1. Fast: Seulement ports web (80, 443, 8080, etc.)")
    print("   2. Normal: ~30 ports courants")
    print("   3. Deep: 1-1024 ports")
    print()

    scanner = ScannerPorts()

    # Afficher les outils disponibles
    print("🔧 OUTILS DISPONIBLES:")
    for outil, disponible in scanner.outils_disponibles.items():
        status = "✅ Disponible" if disponible else "❌ Non disponible"
        print(f"   {outil}: {status}")
    print()

    # Test 1: Fast (ports web seulement)
    print("🏃 TEST 1: Mode FAST (ports web)")
    print("-" * 35)
    try:
        ports_fast = await scanner.scanner("https://juice-shop.herokuapp.com/", intensite='fast')
        print(f"\n✅ RÉSULTAT: {len(ports_fast)} ports ouverts")
        for port, service in sorted(ports_fast.items()):
            print(f"   🔌 {port}: {service}")
    except Exception as e:
        print(f"❌ Erreur: {str(e)}")

    print("\n" + "=" * 50)

    # Test 2: Normal (ports courants)
    print("⚖️  TEST 2: Mode NORMAL (~30 ports)")
    print("-" * 35)
    try:
        ports_normal = await scanner.scanner("http://testphp.vulnweb.com/", intensite='normal')
        print(f"\n✅ RÉSULTAT: {len(ports_normal)} ports ouverts")
        for port, service in sorted(ports_normal.items()):
            print(f"   🔌 {port}: {service}")
    except Exception as e:
        print(f"❌ Erreur: {str(e)}")

    print("\n" + "=" * 50)

    # Test 3: Performance du scanner TCP asynchrone
    print("⚡ TEST 3: Performance scanner TCP asynchrone")
    print("-" * 45)
    try:
        import time
        start_time = time.time()

        # Test du scanner TCP asynchrone directement
        ports_tcp = await scanner._scanner_tcp_asynchrone("testphp.vulnweb.com", scanner.ports_web)
        elapsed = time.time() - start_time

        print(f"\n✅ RÉSULTAT: {len(ports_tcp)} ports ouverts en {elapsed:.2f}s")
        for port in sorted(ports_tcp.keys()):
            print(f"   🔌 {port}: ouvert")
    except Exception as e:
        print(f"❌ Erreur: {str(e)}")

    print("\n" + "=" * 50)
    print("📊 ANALYSE DES AMÉLIORATIONS:")
    print("=" * 50)
    print("🎯 AVANT: Nmap seulement ou ports par défaut")
    print("🎯 APRÈS: Scanner adaptatif multi-outils")
    print()
    print("🔧 Stratégies disponibles:")
    print("   ✅ Masscan: Ultra-rapide (1000 pps)")
    print("   ✅ Rustscan: Rapide et précis")
    print("   ✅ Nmap: Fiable avec détection de services")
    print("   ✅ TCP asynchrone: Fallback rapide")
    print()
    print("⚙️  Intensités:")
    print("   - Fast: Ports web seulement")
    print("   - Normal: ~30 ports courants")
    print("   - Deep: 1-1024 ports")
    print()
    print("🎯 Performance:")
    print("   - Parallélisation: 100 connexions simultanées")
    print("   - Timeouts optimisés: 1s par port")
    print("   - Banner grabbing: Détection de services")
    print()
    print("🚀 L'amélioration est-elle satisfaisante ?")


async def main():
    await test_port_scanner()


if __name__ == "__main__":
    asyncio.run(main())
