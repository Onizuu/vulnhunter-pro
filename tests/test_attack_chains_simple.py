#!/usr/bin/env python3
"""
Test simple des chaînes d'attaque
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.attack_chains import ConstructeurArbresAttaque, OrchestrateurChainesAttaque
from core.models import Vulnerabilite


async def test_simple():
    """Test simple des chaînes d'attaque"""
    print("🔗 TEST SIMPLE CHAÎNES D'ATTAQUE")
    print("=" * 40)

    # Créer des vulnérabilités de test
    vulnerabilites = [
        Vulnerabilite(
            type="SQL Injection",
            severite="CRITIQUE",
            url="https://example.com",
            description="Test vuln"
        ),
        Vulnerabilite(
            type="XSS",
            severite="ÉLEVÉ",
            url="https://example.com",
            description="Test vuln"
        )
    ]

    # Test constructeur d'arbres
    constructeur = ConstructeurArbresAttaque()
    arbre = constructeur.construire_arbre_attaque(vulnerabilites)

    print(f"✅ Arbre d'attaque créé: {arbre.id_chaine}")
    print(f"   Score: {arbre.score_global:.1f}")
    print(f"   Risque: {arbre.niveau_risque}")
    print(f"   Nœuds: {len(arbre.noeuds)}")

    # Test orchestrateur
    orchestrateur = OrchestrateurChainesAttaque()
    rapport = await orchestrateur.analyser_chaine_complete(vulnerabilites)

    print(f"✅ Analyse complète: {len(rapport['chaines_identifiees'])} chaînes")
    print(f"   Priorités: {len(rapport['priorites_remediation'])}")

    print("\n✅ Test des chaînes d'attaque terminé avec succès !")


if __name__ == "__main__":
    asyncio.run(test_simple())
