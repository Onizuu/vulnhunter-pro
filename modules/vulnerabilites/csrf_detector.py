"""
Détecteur de vulnérabilités CSRF (Cross-Site Request Forgery)
"""

import asyncio
from typing import List, Optional
from urllib.parse import urlparse
from loguru import logger
import aiohttp
from bs4 import BeautifulSoup

from core.models import Vulnerabilite


class DetecteurCSRF:
    """
    Détecte l'absence de protection CSRF
    """

    def __init__(self):
        """
        Initialise le détecteur CSRF
        """
        # Tokens CSRF courants à chercher
        self.csrf_token_names = [
            'csrf_token', 'csrf', '_csrf', 'csrftoken', 'token',
            '_token', 'authenticity_token', '__RequestVerificationToken',
            'csrfmiddlewaretoken', 'csrf-token', 'X-CSRF-Token'
        ]
        
        logger.info("Détecteur CSRF initialisé")

    async def detecter(self, url: str) -> List[Vulnerabilite]:
        """
        Détecte les vulnérabilités CSRF
        
        Args:
            url: URL à tester
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités CSRF trouvées
        """
        vulnerabilites = []
        
        try:
            logger.info(f"🔍 Test CSRF: {url}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        return []
                    
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Chercher tous les formulaires
                    formulaires = soup.find_all('form')
                    
                    if not formulaires:
                        logger.debug("Aucun formulaire trouvé")
                        return []
                    
                    logger.debug(f"🔍 {len(formulaires)} formulaire(s) trouvé(s)")
                    
                    # Analyser chaque formulaire
                    formulaires_vulnerables = []
                    
                    for form in formulaires:
                        method = form.get('method', 'get').upper()
                        action = form.get('action', '')
                        
                        # Ne tester que les formulaires POST (changements d'état)
                        if method != 'POST':
                            continue
                        
                        # Chercher un token CSRF
                        a_token_csrf = self._chercher_token_csrf(form)
                        
                        if not a_token_csrf:
                            formulaires_vulnerables.append({
                                'action': action,
                                'method': method
                            })
                            logger.warning(f"⚠️  Formulaire POST sans token CSRF: {action}")
                    
                    # Créer une vulnérabilité si des formulaires vulnérables sont trouvés
                    if formulaires_vulnerables:
                        description = f"{len(formulaires_vulnerables)} formulaire(s) POST sans protection CSRF"
                        
                        if len(formulaires_vulnerables) <= 3:
                            actions = ', '.join([f['action'] for f in formulaires_vulnerables])
                            description += f" (actions: {actions})"
                        
                        vuln = Vulnerabilite(
                            type="CSRF",
                            severite="MOYEN",
                            url=url,
                            description=description,
                            payload="N/A (absence de protection)",
                            preuve=f"{len(formulaires_vulnerables)} formulaires POST sans token CSRF détectés",
                            cvss_score=6.5,
                            remediation="Implémenter des tokens CSRF (Synchronizer Token Pattern ou Double Submit Cookie)"
                        )
                        vulnerabilites.append(vuln)
                        
                        logger.success(f"✅ Vulnérabilité CSRF détectée")
            
            return vulnerabilites
            
        except Exception as e:
            logger.error(f"Erreur test CSRF: {str(e)}")
            return []

    def _chercher_token_csrf(self, form) -> bool:
        """
        Cherche un token CSRF dans un formulaire
        
        Args:
            form: Objet BeautifulSoup du formulaire
            
        Returns:
            bool: True si un token CSRF est trouvé
        """
        # Chercher dans les inputs
        inputs = form.find_all('input')
        
        for input_tag in inputs:
            input_name = input_tag.get('name', '').lower()
            input_id = input_tag.get('id', '').lower()
            
            # Vérifier si le nom ou l'ID correspond à un token CSRF
            for csrf_name in self.csrf_token_names:
                if csrf_name.lower() in input_name or csrf_name.lower() in input_id:
                    logger.debug(f"✅ Token CSRF trouvé: {input_name or input_id}")
                    return True
        
        # Chercher dans les méta tags
        meta_tags = form.find_all('meta')
        for meta in meta_tags:
            meta_name = meta.get('name', '').lower()
            if any(csrf_name.lower() in meta_name for csrf_name in self.csrf_token_names):
                logger.debug(f"✅ Token CSRF trouvé dans meta: {meta_name}")
                return True
        
        return False

