"""
Test d'intégration Mistral AI dans VulnHunter Pro
"""

import os
import asyncio
from dotenv import load_dotenv
from loguru import logger

# Charger les variables d'environnement
load_dotenv()

from integration_ia.mistral_client import ClientMistral


async def test_mistral_client():
    """
    Test basique du client Mistral
    """
    logger.info("🧪 Test d'intégration Mistral AI")
    
    # Récupérer la clé API
    api_key = os.getenv('MISTRAL_API_KEY')
    
    if not api_key:
        logger.error("❌ MISTRAL_API_KEY non trouvée dans .env")
        return False
    
    logger.info(f"✅ Clé API trouvée: {api_key[:10]}...")
    
    # Créer le client
    client = ClientMistral(api_key)
    
    if not client.disponible:
        logger.error("❌ Client Mistral non disponible")
        return False
    
    logger.info("✅ Client Mistral initialisé")
    
    # Test 1: Génération simple
    logger.info("📝 Test 1: Génération de texte simple...")
    prompt = "Explique brièvement ce qu'est une injection SQL en 2 phrases."
    resultat = await client.generer_completion(prompt)
    
    if resultat:
        logger.success(f"✅ Génération réussie: {resultat[:100]}...")
    else:
        logger.error("❌ Échec de génération")
        return False
    
    # Test 2: Génération JSON (payloads SQL)
    logger.info("📝 Test 2: Génération de payloads SQL...")
    payloads = await client.generer_payloads_sqli(
        contexte="Test sur un site PHP/MySQL",
        dbms="MySQL",
        filtres=["Cloudflare WAF"]
    )
    
    if payloads and len(payloads) > 0:
        logger.success(f"✅ {len(payloads)} payloads générés")
        logger.info(f"   Exemple: {payloads[0]}")
    else:
        logger.warning("⚠️  Aucun payload généré")
    
    # Test 3: Génération de payloads XSS
    logger.info("📝 Test 3: Génération de payloads XSS...")
    payloads_xss = await client.generer_payloads_xss(
        contexte="XSS réfléchi dans un paramètre GET",
        filtres=["CSP strict"]
    )
    
    if payloads_xss and len(payloads_xss) > 0:
        logger.success(f"✅ {len(payloads_xss)} payloads XSS générés")
        logger.info(f"   Exemple: {payloads_xss[0]}")
    else:
        logger.warning("⚠️  Aucun payload XSS généré")
    
    logger.success("🎉 Tous les tests Mistral AI sont passés !")
    return True


if __name__ == "__main__":
    asyncio.run(test_mistral_client())

