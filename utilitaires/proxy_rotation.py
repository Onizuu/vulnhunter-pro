"""
Système de rotation de proxies pour la discrétion
"""

import random
from typing import List, Optional
from pathlib import Path
from loguru import logger


class GestionnaireProxies:
    """
    Gère la rotation de proxies
    """

    def __init__(self, fichier_proxies: Optional[str] = None):
        """
        Initialise le gestionnaire de proxies
        
        Args:
            fichier_proxies: Fichier contenant la liste des proxies
        """
        self.proxies: List[str] = []
        self.index_actuel = 0
        
        if fichier_proxies and Path(fichier_proxies).exists():
            self.charger_proxies(fichier_proxies)
        else:
            logger.warning("Pas de fichier de proxies configuré - Mode direct")

    def charger_proxies(self, fichier: str):
        """
        Charge les proxies depuis un fichier
        
        Args:
            fichier: Chemin du fichier
        """
        try:
            with open(fichier, 'r') as f:
                self.proxies = [
                    ligne.strip() 
                    for ligne in f 
                    if ligne.strip() and not ligne.startswith('#')
                ]
            
            logger.info(f"✅ {len(self.proxies)} proxies chargés")
        
        except Exception as e:
            logger.error(f"Erreur chargement proxies: {str(e)}")

    def obtenir_proxy(self, aleatoire: bool = True) -> Optional[str]:
        """
        Obtient un proxy
        
        Args:
            aleatoire: Si True, choisit un proxy aléatoire
            
        Returns:
            str: URL du proxy ou None
        """
        if not self.proxies:
            return None
        
        if aleatoire:
            return random.choice(self.proxies)
        else:
            # Rotation séquentielle
            proxy = self.proxies[self.index_actuel]
            self.index_actuel = (self.index_actuel + 1) % len(self.proxies)
            return proxy

    def obtenir_dict_proxy(self, aleatoire: bool = True) -> Optional[dict]:
        """
        Retourne un proxy au format dict pour requests/aiohttp
        
        Args:
            aleatoire: Si True, choisit un proxy aléatoire
            
        Returns:
            dict: Dictionnaire de proxy ou None
        """
        proxy = self.obtenir_proxy(aleatoire)
        
        if proxy:
            return {
                'http': proxy,
                'https': proxy
            }
        
        return None

    def valider_proxy(self, proxy: str) -> bool:
        """
        Valide qu'un proxy fonctionne
        
        Args:
            proxy: URL du proxy
            
        Returns:
            bool: True si le proxy fonctionne
        """
        # TODO: Implémenter validation réelle
        return True

    def supprimer_proxy(self, proxy: str):
        """
        Supprime un proxy défaillant
        
        Args:
            proxy: Proxy à supprimer
        """
        if proxy in self.proxies:
            self.proxies.remove(proxy)
            logger.warning(f"Proxy supprimé: {proxy}")

