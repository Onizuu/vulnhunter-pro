"""
Rate limiter pour éviter de surcharger les cibles
"""

import asyncio
import time
from typing import Dict
from loguru import logger


class RateLimiter:
    """
    Limite le nombre de requêtes par seconde
    """

    def __init__(self, requetes_par_seconde: int = 10):
        """
        Initialise le rate limiter
        
        Args:
            requetes_par_seconde: Nombre de requêtes autorisées par seconde
        """
        self.requetes_par_seconde = requetes_par_seconde
        self.delai_entre_requetes = 1.0 / requetes_par_seconde
        self.derniere_requete: Dict[str, float] = {}
        self.lock = asyncio.Lock()

    async def attendre(self, cle: str = "default"):
        """
        Attend si nécessaire pour respecter le rate limit
        
        Args:
            cle: Clé pour identifier différents rate limits
        """
        async with self.lock:
            maintenant = time.time()
            
            if cle in self.derniere_requete:
                temps_ecoule = maintenant - self.derniere_requete[cle]
                
                if temps_ecoule < self.delai_entre_requetes:
                    attente = self.delai_entre_requetes - temps_ecoule
                    logger.debug(f"Rate limiting: attente de {attente:.2f}s")
                    await asyncio.sleep(attente)
            
            self.derniere_requete[cle] = time.time()

    def set_rate(self, requetes_par_seconde: int):
        """
        Change le taux de requêtes
        
        Args:
            requetes_par_seconde: Nouveau taux
        """
        self.requetes_par_seconde = requetes_par_seconde
        self.delai_entre_requetes = 1.0 / requetes_par_seconde
        logger.info(f"Rate limit changé: {requetes_par_seconde} req/s")

