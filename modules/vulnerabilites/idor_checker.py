"""
Vérificateur IDOR (Insecure Direct Object Reference)
"""

import asyncio
from typing import List
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class VerificateurIDOR:
    """
    Détecte les références d'objets directes non sécurisées
    """

    async def verifier(self, url: str) -> List[Vulnerabilite]:
        """
        Vérifie les vulnérabilités IDOR
        """
        vulnerabilites = []
        
        try:
            logger.info(f"🔍 Test IDOR: {url}")
            
            # Tester différents IDs
            async with aiohttp.ClientSession() as session:
                reponses = {}
                
                for user_id in range(1, 21):
                    test_url = url.replace('1', str(user_id))
                    
                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            reponses[user_id] = {
                                'status': response.status,
                                'taille': len(await response.text())
                            }
                    
                    except:
                        continue
                    
                    await asyncio.sleep(0.1)
                
                # Analyser les résultats
                acces_autorises = sum(1 for r in reponses.values() if r['status'] == 200)
                
                # CORRECTION : Ne plus générer de faux positifs
                # Un vrai IDOR nécessite une analyse contextuelle avec authentification
                # Le simple fait que des IDs soient accessibles n'est PAS une vulnérabilité
                if acces_autorises > 5:
                    logger.debug(f"ℹ️  {acces_autorises} IDs accessibles (comportement normal)")
                    # Ne plus créer de vulnérabilité IDOR sans preuve d'accès non autorisé
                    # TODO: Implémenter un vrai test IDOR avec deux sessions utilisateurs
        
        except Exception as e:
            logger.debug(f"Erreur test IDOR: {str(e)}")
        
        return vulnerabilites

