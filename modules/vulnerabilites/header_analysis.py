"""
Analyseur de headers de sécurité HTTP
"""

from typing import List
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class AnalyseurHeaders:
    """
    Analyse les headers de sécurité HTTP manquants ou mal configurés
    """

    def __init__(self):
        self.headers_securite = {
            'Strict-Transport-Security': 'HSTS manquant - trafic HTTP non sécurisé',
            'Content-Security-Policy': 'CSP manquant - risque XSS',
            'X-Frame-Options': 'X-Frame-Options manquant - risque clickjacking',
            'X-Content-Type-Options': 'X-Content-Type-Options manquant - risque MIME sniffing',
            'Referrer-Policy': 'Referrer-Policy manquant - fuite d\'informations',
            'Permissions-Policy': 'Permissions-Policy manquant',
        }

    async def analyser(self, url: str) -> List[Vulnerabilite]:
        """
        Analyse les headers de sécurité
        """
        vulnerabilites = []
        
        try:
            logger.info(f"🔍 Analyse headers: {url}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    headers = dict(response.headers)
                    
                    # Vérifier chaque header de sécurité
                    for header, description in self.headers_securite.items():
                        if header not in headers:
                            vuln = Vulnerabilite(
                                type="Header de sécurité manquant",
                                severite="FAIBLE",
                                url=url,
                                description=description,
                                payload=f"Header manquant: {header}",
                                preuve=f"{header} non présent dans les headers",
                                cvss_score=3.0,
                                remediation=f"Ajouter le header {header} à la configuration du serveur"
                            )
                            vulnerabilites.append(vuln)
                    
                    # Vérifier les headers dangereux
                    if 'Server' in headers:
                        vuln = Vulnerabilite(
                            type="Fuite d'information",
                            severite="INFO",
                            url=url,
                            description="Header Server révèle des informations sur le serveur",
                            payload="Server header présent",
                            preuve=f"Server: {headers['Server']}",
                            cvss_score=1.0,
                            remediation="Masquer ou supprimer le header Server"
                        )
                        vulnerabilites.append(vuln)
        
        except Exception as e:
            logger.debug(f"Erreur analyse headers: {str(e)}")
        
        return vulnerabilites

