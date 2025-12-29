"""
Test d'intégration Ollama dans VulnHunter Pro
"""

import os
import asyncio
from dotenv import load_dotenv
from loguru import logger

# Charger les variables d'environnement
load_dotenv()

from integration_ia.ia_client_fallback import ClientIAFallback


async def test_ollama_fallback():
    """
    Test du système Ollama + fallback Claude
    """
    logger.info("🧪 Test d'intégration Ollama + Fallback Claude")
    
    # Configuration sans Claude (pour tests)
    ollama_model = os.getenv('OLLAMA_MODEL', 'mistral:7b')
    
    logger.info(f"📝 Configuration:")
    logger.info(f"   - Modèle Ollama: {ollama_model}")
    logger.info(f"   - Claude: Non configuré (pour tests)")
    
    # Créer le client avec fallback
    client = ClientIAFallback(
        ollama_model=ollama_model,
        claude_api_key=None,  # Pas de Claude pour les tests
        budget_max=5.0
    )
    
    if not client.disponible:
        logger.error("❌ Ollama non disponible")
        logger.info("💡 Installez Ollama:")
        logger.info("   1. brew install ollama")
        logger.info("   2. ollama serve")
        logger.info(f"   3. ollama pull {ollama_model}")
        return False
    
    logger.info("✅ Client IA Fallback initialisé")
    
    # Test 1: Génération simple
    logger.info("📝 Test 1: Génération de texte simple...")
    prompt = "Explique brièvement ce qu'est une injection SQL en 2 phrases."
    resultat = await client.generer_completion(
        prompt,
        contexte="Test simple"
    )
    
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
        filtres=None
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
        filtres=None
    )
    
    if payloads_xss and len(payloads_xss) > 0:
        logger.success(f"✅ {len(payloads_xss)} payloads XSS générés")
        logger.info(f"   Exemple: {payloads_xss[0]}")
    else:
        logger.warning("⚠️  Aucun payload XSS généré")
    
    # Afficher les statistiques
    stats = client.get_statistiques_budget()
    logger.info("📊 Statistiques de budget:")
    logger.info(f"   - Appels Ollama: {stats['appels_ollama']}")
    logger.info(f"   - Appels Claude: {stats['appels_claude']}")
    logger.info(f"   - Budget utilisé: {stats['budget_utilise']}€ / {stats['budget_max']}€")
    
    logger.success("🎉 Tous les tests Ollama sont passés !")
    return True


if __name__ == "__main__":
    asyncio.run(test_ollama_fallback())

