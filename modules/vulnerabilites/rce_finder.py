"""
Chercheur de vulnérabilités RCE (Remote Code Execution)
"""

import asyncio
import time
from typing import Optional
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class ChercheurRCE:
    """
    Détecte les vulnérabilités d'exécution de code à distance
    """

    def __init__(self, client_ia):
        self.client_ia = client_ia
        
        # ⭐ PHASE 5: Marqueur unique pour confirmation RCE
        import time
        self.marqueur_unique = f"VULNHUNTER_RCE_{int(time.time())}"
        
        # ⭐ PHASE 5: Payloads RCE sûrs (non destructifs) - avec marqueur unique
        self.payloads_linux = [
            f"; echo '{self.marqueur_unique}' #",  # ⭐ NOUVEAU: Marqueur unique
            f"| echo '{self.marqueur_unique}' #",  # ⭐ NOUVEAU
            f"`echo '{self.marqueur_unique}'`",  # ⭐ NOUVEAU
            f"$(echo '{self.marqueur_unique}')",  # ⭐ NOUVEAU
            "; whoami #",
            "| whoami #",
            "& whoami &",
            "`whoami`",
            "$(whoami)",
            "; id #",
            "| id #",
            "; echo 'VULNHUNTER_RCE' #",  # Ancien marqueur (fallback)
            "| echo 'VULNHUNTER_RCE' #",
        ]
        
        self.payloads_windows = [
            f"& echo {self.marqueur_unique} &",  # ⭐ NOUVEAU: Marqueur unique
            "& whoami &",
            "| whoami |",
            "& echo VULNHUNTER_RCE &",  # Ancien marqueur (fallback)
        ]

    async def chercher(self, url: str, parametres_decouverts: dict = None) -> Optional[Vulnerabilite]:
        """
        Cherche des vulnérabilités RCE
        
        Args:
            url: URL à tester
            parametres_decouverts: Paramètres découverts automatiquement (optionnel)
            
        Returns:
            Vulnerabilite: Vulnérabilité RCE si trouvée
        """
        try:
            logger.info(f"🔍 Recherche RCE: {url}")
            
            # ⭐ NOUVEAU: Tester avec les paramètres découverts
            if parametres_decouverts:
                params_get = parametres_decouverts.get('get', [])
                params_post = parametres_decouverts.get('post', [])
                
                # ⭐ PHASE 5: Tester les paramètres GET - augmenté
                for param_name in params_get[:15]:  # ⭐ Augmenté de 10 à 15 paramètres
                    vuln = await self._tester_parametre(url, param_name, self.payloads_linux, "Linux", "GET")
                    if vuln:
                        return vuln
                
                # ⭐ PHASE 5: Tester les paramètres POST - augmenté
                for param_name in params_post[:15]:  # ⭐ Augmenté de 10 à 15 paramètres
                    vuln = await self._tester_parametre(url, param_name, self.payloads_linux, "Linux", "POST")
                    if vuln:
                        return vuln
            
            # Tests classiques avec paramètres génériques
            # Tests avec payloads Linux
            vuln_linux = await self._tester_payloads(url, self.payloads_linux, "Linux")
            if vuln_linux:
                return vuln_linux
            
            # Tests avec payloads Windows
            vuln_windows = await self._tester_payloads(url, self.payloads_windows, "Windows")
            if vuln_windows:
                return vuln_windows
            
            # Tests temporels (sleep)
            vuln_temporel = await self._tester_rce_temporel(url)
            if vuln_temporel:
                return vuln_temporel
        
        except Exception as e:
            logger.debug(f"Erreur recherche RCE: {str(e)}")
        
        return None

    async def _tester_parametre(
        self,
        url: str,
        param_name: str,
        payloads: list,
        systeme: str,
        method: str = "GET"
    ) -> Optional[Vulnerabilite]:
        """
        Teste RCE sur un paramètre spécifique
        
        Args:
            url: URL à tester
            param_name: Nom du paramètre à tester
            payloads: Liste de payloads à tester
            systeme: Système cible (Linux/Windows)
            method: Méthode HTTP (GET/POST)
            
        Returns:
            Vulnerabilite: Vulnérabilité RCE si trouvée
        """
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            async with aiohttp.ClientSession() as session:
                # ⭐ PHASE 5: Tester plus de payloads (jusqu'à 10)
                for payload in payloads[:10]:  # ⭐ Augmenté de 5 à 10 payloads
                    try:
                        if method == "GET":
                            async with session.get(
                                test_url,
                                params={param_name: payload},
                                timeout=aiohttp.ClientTimeout(total=10)
                            ) as response:
                                contenu = await response.text()
                                
                                if self._verifier_rce(contenu, payload):
                                    logger.success(f"✅ RCE {systeme} détecté sur paramètre '{param_name}'!")
                                    
                                    return Vulnerabilite(
                                        type="RCE",
                                        severite="CRITIQUE",
                                        url=f"{test_url}?{param_name}={payload}",
                                        description=f"Exécution de code à distance ({systeme}) détectée dans le paramètre '{param_name}'",
                                        payload=payload,
                                        preuve=contenu[:500],
                                        cvss_score=9.9,
                                        remediation="Ne jamais exécuter des commandes système avec des entrées utilisateur"
                                    )
                        else:  # POST
                            async with session.post(
                                test_url,
                                data={param_name: payload},
                                timeout=aiohttp.ClientTimeout(total=10)
                            ) as response:
                                contenu = await response.text()
                                
                                if self._verifier_rce(contenu, payload):
                                    logger.success(f"✅ RCE {systeme} détecté sur paramètre '{param_name}'!")
                                    
                                    return Vulnerabilite(
                                        type="RCE",
                                        severite="CRITIQUE",
                                        url=test_url,
                                        description=f"Exécution de code à distance ({systeme}) détectée dans le paramètre POST '{param_name}'",
                                        payload=payload,
                                        preuve=contenu[:500],
                                        cvss_score=9.9,
                                        remediation="Ne jamais exécuter des commandes système avec des entrées utilisateur"
                                    )
                    
                    except Exception:
                        continue
                    
                    await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.debug(f"Erreur test RCE paramètre: {str(e)}")
        
        return None

    async def _tester_payloads(
        self,
        url: str,
        payloads: list,
        systeme: str
    ) -> Optional[Vulnerabilite]:
        """
        Teste une liste de payloads RCE
        """
        async with aiohttp.ClientSession() as session:
            for payload in payloads:
                try:
                    # Test en GET
                    async with session.get(
                        url,
                        params={'cmd': payload},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        contenu = await response.text()
                        
                        if self._verifier_rce(contenu, payload):
                            logger.success(f"✅ RCE {systeme} détecté!")
                            
                            return Vulnerabilite(
                                type="RCE",
                                severite="CRITIQUE",
                                url=url,
                                description=f"Exécution de code à distance ({systeme}) détectée",
                                payload=payload,
                                preuve=contenu[:500],
                                cvss_score=9.9,
                                remediation="Ne jamais exécuter des commandes système avec des entrées utilisateur"
                            )
                    
                    # Test en POST
                    async with session.post(
                        url,
                        data={'cmd': payload},
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        contenu = await response.text()
                        
                        if self._verifier_rce(contenu, payload):
                            logger.success(f"✅ RCE {systeme} détecté!")
                            
                            return Vulnerabilite(
                                type="RCE",
                                severite="CRITIQUE",
                                url=url,
                                description=f"Exécution de code à distance ({systeme}) détectée",
                                payload=payload,
                                preuve=contenu[:500],
                                cvss_score=9.9,
                                remediation="Ne jamais exécuter des commandes système avec des entrées utilisateur"
                            )
                
                except Exception:
                    continue
                
                await asyncio.sleep(0.1)
        
        return None

    async def _tester_rce_temporel(self, url: str) -> Optional[Vulnerabilite]:
        """
        ⭐ PHASE 5: Teste les RCE avec des commandes sleep - amélioré
        """
        # ⭐ PHASE 5: Payloads sleep étendus
        payloads_sleep = [
            "; sleep 5 #",
            "; sleep 10 #",  # ⭐ NOUVEAU: Délai plus long pour confirmation
            "| sleep 5 #",
            "| sleep 10 #",  # ⭐ NOUVEAU
            "& timeout 5 &",
            "`sleep 5`",  # ⭐ NOUVEAU
            "$(sleep 5)",  # ⭐ NOUVEAU
        ]
        
        async with aiohttp.ClientSession() as session:
            # ⭐ PHASE 5: Mesurer temps normal (moyenne sur 3 requêtes)
            temps_normaux = []
            for _ in range(3):  # ⭐ NOUVEAU: 3 mesures pour moyenne
                debut = time.time()
                try:
                    await session.get(url, timeout=aiohttp.ClientTimeout(total=5))
                    temps_normaux.append(time.time() - debut)
                except:
                    pass
                await asyncio.sleep(0.2)
            
            temps_normal = sum(temps_normaux) / len(temps_normaux) if temps_normaux else 1.0
            
            for payload in payloads_sleep:
                try:
                    debut = time.time()
                    # ⭐ PHASE 5: Timeout adaptatif selon le sleep
                    timeout_sec = 20 if 'sleep 10' in payload or 'timeout 10' in payload else 15
                    await session.get(
                        url,
                        params={'cmd': payload},
                        timeout=aiohttp.ClientTimeout(total=timeout_sec)
                    )
                    temps_avec_payload = time.time() - debut
                    
                    # ⭐ PHASE 5: Seuil plus strict (>3.5s pour être sûr)
                    if temps_avec_payload > (temps_normal + 3.5):
                        logger.success(
                            f"✅ RCE temporel détecté: {temps_normal:.2f}s -> {temps_avec_payload:.2f}s"
                        )
                        
                        return Vulnerabilite(
                            type="RCE",
                            severite="CRITIQUE",
                            url=url,
                            description="Exécution de code à distance (temporelle) détectée",
                            payload=payload,
                            preuve=f"Délai confirmé: {temps_avec_payload:.2f}s vs normal: {temps_normal:.2f}s",
                            cvss_score=9.9,
                            remediation="Ne jamais exécuter des commandes système"
                        )
                
                except:
                    continue
                
                await asyncio.sleep(0.5)
        
        return None

    def _verifier_rce(self, contenu: str, payload: str) -> bool:
        """
        ⭐ PHASE 5: Vérifie si la RCE est réussie - amélioré avec marqueur unique
        """
        # ⭐ PHASE 5: Vérifier d'abord le marqueur unique (plus fiable)
        if hasattr(self, 'marqueur_unique') and self.marqueur_unique in contenu:
            logger.success(f"✅ RCE confirmée avec marqueur unique: {self.marqueur_unique}")
            return True
        
        # Fallback sur l'ancien marqueur
        if 'VULNHUNTER_RCE' in contenu:
            return True
        
        # ⭐ PHASE 5: Vérifier sortie whoami/id (plus strict)
        contenu_lower = contenu.lower()
        if 'root' in contenu_lower or 'www-data' in contenu_lower or 'apache' in contenu_lower:
            # Vérifier aussi que ce n'est pas juste dans un commentaire HTML
            if '<' not in contenu[:100] or 'root' in contenu[:200]:  # Probablement pas HTML
                return True
        
        # Vérifier sortie id
        if 'uid=' in contenu and 'gid=' in contenu:
            return True
        
        return False

