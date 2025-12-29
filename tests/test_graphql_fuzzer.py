"""
Test du GraphQL Fuzzer
"""

import asyncio
import sys
import os

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import aiohttp
from modules.vulnerabilites.graphql_fuzzer import GraphQLFuzzer
from loguru import logger

async def test_graphql_fuzzer():
    # Test contre un endpoint GraphQL public (countries API)
    url = "https://countries.trevorblades.com/"
    
    # Créer une session aiohttp
    timeout = aiohttp.ClientTimeout(total=30)
    connector = aiohttp.TCPConnector(limit=20, ssl=False)
    
    async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
        fuzzer = GraphQLFuzzer(session, auth_config={})
        
        logger.info(f"🧪 Test du GraphQL fuzzer sur {url}")
        
        # Lancer le scan
        vulnerabilites = await fuzzer.scanner(url)
        
        # Afficher les résultats
        logger.info(f"\n{'='*60}")
        logger.info(f"📊 RÉSULTATS DU SCAN GraphQL")
        logger.info(f"{'='*60}")
        logger.info(f"Endpoint: {url}")
        logger.info(f"Vulnérabilités trouvées: {len(vulnerabilites)}")
        logger.info(f"{'='*60}\n")
        
        for i, vuln in enumerate(vulnerabilites, 1):
            logger.info(f"{i}. {vuln.type} - {vuln.severite}")
            logger.info(f"   Description: {vuln.description}")
            logger.info(f"   Remédiation: {vuln.remediation}")
            logger.info("")

if __name__ == "__main__":
    asyncio.run(test_graphql_fuzzer())
