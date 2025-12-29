#!/usr/bin/env python3
"""
Test simple des métriques de conformité
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from core.compliance_metrics import CalculateurOWASPRisk, CalculateurCVSS, VerificateurCompliance
from core.models import Vulnerabilite


async def test_simple():
    """Test simple des métriques"""
    print("📊 TEST SIMPLE MÉTRIQUES DE CONFORMITÉ")
    print("=" * 50)

    # Créer une vulnérabilité de test
    vuln = Vulnerabilite(
        type="SQL Injection",
        severite="CRITIQUE",
        url="https://example.com",
        description="Test vulnerability"
    )

    # Test OWASP Risk
    calculateur_owasp = CalculateurOWASPRisk()
    score_owasp = calculateur_owasp.calculer_risque_owasp(vuln)

    print(f"✅ OWASP Score: {score_owasp.overall_score:.1f} ({score_owasp.severity.value})")

    # Test CVSS
    calculateur_cvss = CalculateurCVSS()
    score_cvss = calculateur_cvss.calculer_score_cvss(vuln)

    print(f"✅ CVSS Score: {score_cvss.base_score:.1f} ({score_cvss.severity.value})")

    # Test Compliance
    verificateur = VerificateurCompliance()
    rapport = verificateur.verifier_conformite([vuln], 'pci_dss')

    conforme = "✅ Conforme" if rapport['conforme'] else "❌ Non conforme"
    print(f"✅ PCI-DSS: {conforme} ({rapport['score_conformite']:.1f}%)")

    print("\n✅ Test des métriques terminé avec succès !")


if __name__ == "__main__":
    asyncio.run(test_simple())
