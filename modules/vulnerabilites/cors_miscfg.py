"""
Analyseur de mauvaises configurations CORS
"""

from typing import Optional
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class AnalyseurCORS:
    """
    Analyse les configurations CORS dangereuses
    """

    async def analyser(self, url: str) -> Optional[Vulnerabilite]:
        """
        Analyse la configuration CORS
        """
        try:
            logger.info(f"🔍 Analyse CORS: {url}")
            
            async with aiohttp.ClientSession() as session:
                headers = {'Origin': 'https://evil.com'}
                
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    cors_header = response.headers.get('Access-Control-Allow-Origin', '')
                    credentials = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    # Vérifier si origine malveillante acceptée
                    if cors_header == '*' or cors_header == 'https://evil.com':
                        logger.warning("⚠️  Mauvaise configuration CORS détectée")
                        
                        severite = "CRITIQUE" if credentials == "true" else "MOYEN"
                        
                        return Vulnerabilite(
                            type="Mauvaise configuration CORS",
                            severite=severite,
                            url=url,
                            description="CORS mal configuré permettant accès depuis n'importe quelle origine",
                            payload="Origin: https://evil.com",
                            preuve=f"Access-Control-Allow-Origin: {cors_header}",
                            cvss_score=7.5 if severite == "CRITIQUE" else 5.0,
                            remediation="Configurer CORS avec une liste blanche d'origines autorisées"
                        )
        
        except Exception as e:
            logger.debug(f"Erreur analyse CORS: {str(e)}")
        
        return None

