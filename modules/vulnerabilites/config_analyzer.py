"""
Analyseur de configuration approfondi
Détection des misconfigurations cloud, fuites de secrets, debug modes, credentials par défaut
"""

import asyncio
import re
import json
import base64
from typing import List, Dict, Tuple, Optional
from urllib.parse import urlparse
from loguru import logger
import aiohttp

from core.models import Vulnerabilite


class AnalyseurConfiguration:
    """
    Analyse approfondie des configurations pour détecter les erreurs courantes
    """

    def __init__(self, client_ia=None):
        self.client_ia = client_ia
        self.timeout = 10

        # Patterns pour détecter les secrets
        self.secret_patterns = {
            'github_token': [
                r'github[_-]?token[=:]\s*[\'"]([a-f0-9]{40})[\'"]',
                r'ghp_[a-zA-Z0-9]{36}',
                r'github_pat_[a-zA-Z0-9_]{82}'
            ],
            'slack_token': [
                r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+',
                r'xoxp-[0-9]+-[0-9]+-[a-zA-Z0-9]+',
                r'xoxo-[0-9]+-[0-9]+-[a-zA-Z0-9]+'
            ],
            'aws_access_key': [
                r'AKIA[0-9A-Z]{16}',
                r'aws_access_key_id[=:]\s*[\'"](AKIA[0-9A-Z]{16})[\'"]'
            ],
            'aws_secret_key': [
                r'aws_secret_access_key[=:]\s*[\'"]([a-zA-Z0-9+/]{40})[\'"]'
            ],
            'azure_storage_key': [
                r'AccountKey=[a-zA-Z0-9+/=]{88}'
            ],
            'jwt_secret': [
                r'jwt[_-]?secret[=:]\s*[\'"]([^\'"]{10,})[\'"]',
                r'secret[_-]?key[=:]\s*[\'"]([^\'"]{10,})[\'"]'
            ],
            'database_password': [
                r'(?:db|database|mysql|postgres|mongodb)[_-]?password[=:]\s*[\'"]([^\'"]{3,})[\'"]',
                r'password[=:]\s*[\'"](admin|root|password|123456|qwerty)[\'"]'
            ],
            'private_key': [
                r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----'
            ]
        }

        # Endpoints cloud courants à vérifier
        self.cloud_endpoints = {
            'aws_s3': [
                's3.amazonaws.com',
                's3-{region}.amazonaws.com',
                '{bucket}.s3.amazonaws.com'
            ],
            'azure_blob': [
                '{account}.blob.core.windows.net',
                '{account}.file.core.windows.net'
            ],
            'gcp_storage': [
                'storage.googleapis.com/{bucket}',
                'storage.cloud.google.com/{bucket}'
            ]
        }

        # Databases exposées courantes
        self.database_checks = {
            'mongodb': {
                'port': 27017,
                'check_command': '{"serverStatus": 1}',
                'vulnerable_response': ['ok', 'version']
            },
            'redis': {
                'port': 6379,
                'check_command': 'INFO',
                'vulnerable_response': ['redis_version', '# Server']
            },
            'elasticsearch': {
                'port': 9200,
                'path': '/_cluster/health',
                'vulnerable_response': ['cluster_name', 'status']
            },
            'couchdb': {
                'port': 5984,
                'path': '/',
                'vulnerable_response': ['couchdb', 'version']
            }
        }

        # Credentials par défaut courants
        self.default_credentials = {
            'admin': ['admin', 'password', '123456', 'admin123'],
            'root': ['root', 'toor', 'password', '123456'],
            'user': ['user', 'password', '123456'],
            'guest': ['guest', 'password', '123456'],
            'test': ['test', 'password', '123456', 'testing'],
            'api': ['api', 'password', 'key', 'token'],
            'backup': ['backup', 'password', '123456'],
            'ftp': ['ftp', 'anonymous', 'password'],
            'mysql': ['root', 'password', '123456'],
            'postgres': ['postgres', 'password', '123456'],
            'mongodb': ['admin', 'password', '123456']
        }

        # Modes debug et développement
        self.debug_patterns = {
            'php': [
                r'display_errors\s*=\s*On',
                r'error_reporting\s*=\s*E_ALL',
                r'debug\s*=\s*true',
                r'DEBUG.*true'
            ],
            'asp_net': [
                r'<compilation debug="true"',
                r'<customErrors mode="Off"',
                r'DEBUG.*true'
            ],
            'java': [
                r'logging\.level\.root=DEBUG',
                r'spring\.profiles\.active=dev',
                r'DEBUG.*true'
            ],
            'javascript': [
                r'console\.log',
                r'debug.*true',
                r'NODE_ENV.*development'
            ]
        }

    async def analyser(self, url: str, technologies: Dict[str, str]) -> List[Vulnerabilite]:
        """
        Analyse complète de configuration pour détecter les erreurs courantes
        """
        vulnerabilites = []

        try:
            logger.info(f"🔧 Analyse de configuration approfondie: {url}")

            # 1. Analyse des fuites de secrets
            logger.debug("🔐 Recherche de fuites de secrets...")
            secrets_vulns = await self._analyser_fuites_secrets(url, technologies)
            vulnerabilites.extend(secrets_vulns)

            # 2. Analyse des misconfigurations cloud
            logger.debug("☁️  Analyse des misconfigurations cloud...")
            cloud_vulns = await self._analyser_misconfigurations_cloud(url)
            vulnerabilites.extend(cloud_vulns)

            # 3. Analyse des bases de données exposées
            logger.debug("🗄️  Analyse des bases de données exposées...")
            db_vulns = await self._analyser_databases_exposees(url)
            vulnerabilites.extend(db_vulns)

            # 4. Analyse des modes debug
            logger.debug("🐛 Analyse des modes debug...")
            debug_vulns = await self._analyser_modes_debug(url, technologies)
            vulnerabilites.extend(debug_vulns)

            # 5. Analyse des credentials par défaut
            logger.debug("🔑 Analyse des credentials par défaut...")
            creds_vulns = await self._analyser_credentials_defaut(url, technologies)
            vulnerabilites.extend(creds_vulns)

            # 6. Analyse des fichiers sensibles
            logger.debug("📁 Analyse des fichiers sensibles...")
            files_vulns = await self._analyser_fichiers_sensibles(url)
            vulnerabilites.extend(files_vulns)

            # Éliminer les doublons
            vulnerabilites = self._dedupliquer_vulnerabilites(vulnerabilites)

            if vulnerabilites:
                logger.success(f"🚨 {len(vulnerabilites)} problème(s) de configuration détecté(s)")
            else:
                logger.info("✅ Aucune vulnérabilité de configuration détectée")

        except Exception as e:
            logger.error(f"Erreur analyse configuration: {str(e)}")

        return vulnerabilites

    async def _analyser_fuites_secrets(self, url: str, technologies: Dict[str, str]) -> List[Vulnerabilite]:
        """Analyse les fuites de secrets dans le contenu web"""
        vulnerabilites = []

        try:
            # Récupérer le contenu de plusieurs pages
            pages_a_analyser = [
                url,
                f"{url}/config",
                f"{url}/.env",
                f"{url}/settings",
                f"{url}/api/config",
                f"{url}/.git/config",
                f"{url}/package.json",
                f"{url}/composer.json"
            ]

            async with aiohttp.ClientSession() as session:
                for page_url in pages_a_analyser:
                    try:
                        async with session.get(
                            page_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            allow_redirects=False
                        ) as response:

                            if response.status == 200:
                                contenu = await response.text()

                                # Analyser avec chaque pattern de secret
                                for secret_type, patterns in self.secret_patterns.items():
                                    for pattern in patterns:
                                        matches = re.findall(pattern, contenu, re.IGNORECASE | re.MULTILINE)
                                        for match in matches:
                                            # Nettoyer le match pour éviter de logger des vrais secrets
                                            clean_match = match[:10] + "..." if len(match) > 10 else match

                                            vuln = Vulnerabilite(
                                                type=f"Fuite de secret: {secret_type}",
                                                severite="CRITIQUE",
                                                url=page_url,
                                                description=f"Secret {secret_type} exposé dans le contenu web",
                                                payload=f"Pattern trouvé: {pattern}",
                                                preuve=f"Secret détecté: {clean_match}",
                                                cvss_score=9.8,
                                                remediation="Supprimer immédiatement les secrets du code source et régénérer les clés compromises"
                                            )
                                            vulnerabilites.append(vuln)

                    except:
                        continue

        except Exception as e:
            logger.debug(f"Erreur analyse fuites secrets: {str(e)}")

        return vulnerabilites

    async def _analyser_misconfigurations_cloud(self, url: str) -> List[Vulnerabilite]:
        """Analyse les misconfigurations cloud courantes"""
        vulnerabilites = []

        try:
            parsed = urlparse(url)
            domaine = parsed.netloc

            async with aiohttp.ClientSession() as session:
                # Test AWS S3 buckets
                for bucket_name in self._generer_noms_buckets_potentiels(domaine):
                    try:
                        s3_url = f"https://{bucket_name}.s3.amazonaws.com"
                        async with session.get(s3_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                            if response.status == 200:
                                contenu = await response.text()
                                if not self._est_bucket_prive(contenu):
                                    vuln = Vulnerabilite(
                                        type="Misconfiguration AWS S3",
                                        severite="ÉLEVÉ",
                                        url=s3_url,
                                        description="Bucket AWS S3 potentiellement exposé publiquement",
                                        payload=f"Bucket: {bucket_name}",
                                        preuve="Bucket accessible sans authentification",
                                        cvss_score=7.5,
                                        remediation="Configurer les permissions S3 pour restreindre l'accès public"
                                    )
                                    vulnerabilites.append(vuln)

                    except:
                        continue

                # Test Azure Storage
                for account in self._generer_noms_azure_potentiels(domaine):
                    try:
                        azure_url = f"https://{account}.blob.core.windows.net"
                        async with session.get(f"{azure_url}?restype=service&comp=properties",
                                             timeout=aiohttp.ClientTimeout(total=5)) as response:
                            if response.status == 200:
                                vuln = Vulnerabilite(
                                    type="Misconfiguration Azure Storage",
                                    severite="ÉLEVÉ",
                                    url=azure_url,
                                    description="Storage Azure potentiellement mal configuré",
                                    payload=f"Account: {account}",
                                    preuve="Storage accessible sans authentification appropriée",
                                    cvss_score=7.5,
                                    remediation="Configurer les permissions Azure Storage pour restreindre l'accès"
                                )
                                vulnerabilites.append(vuln)

                    except:
                        continue

        except Exception as e:
            logger.debug(f"Erreur analyse cloud misconfigurations: {str(e)}")

        return vulnerabilites

    async def _analyser_databases_exposees(self, url: str) -> List[Vulnerabilite]:
        """Analyse les bases de données potentiellement exposées"""
        vulnerabilites = []

        try:
            parsed = urlparse(url)
            host = parsed.hostname

            for db_name, db_config in self.database_checks.items():
                try:
                    port = db_config['port']

                    # Test de connexion directe à la base de données
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=3
                    )

                    if 'check_command' in db_config:
                        # Envoyer une commande de vérification
                        writer.write((db_config['check_command'] + '\n').encode())
                        await writer.drain()

                        # Lire la réponse
                        data = await asyncio.wait_for(
                            reader.read(1024), timeout=3
                        )
                        response = data.decode('utf-8', errors='ignore')

                        # Vérifier si la réponse indique une base exposée
                        vulnerable = any(keyword in response for keyword in db_config['vulnerable_response'])

                        if vulnerable:
                            vuln = Vulnerabilite(
                                type=f"Base de données exposée: {db_name.upper()}",
                                severite="CRITIQUE",
                                url=f"{host}:{port}",
                                description=f"Base de données {db_name} accessible sans authentification",
                                payload=f"Port {port} ouvert",
                                preuve=f"Réponse {db_name}: {response[:100]}...",
                                cvss_score=9.8,
                                remediation=f"Configurer l'authentification et le firewall pour {db_name}"
                            )
                            vulnerabilites.append(vuln)

                    writer.close()
                    await writer.wait_closed()

                except:
                    continue

        except Exception as e:
            logger.debug(f"Erreur analyse databases exposées: {str(e)}")

        return vulnerabilites

    async def _analyser_modes_debug(self, url: str, technologies: Dict[str, str]) -> List[Vulnerabilite]:
        """Analyse les modes debug et développement activés"""
        vulnerabilites = []

        try:
            # Déterminer les technologies pour cibler les patterns appropriés
            tech_keys = [t.lower() for t in technologies.keys()]

            # Pages à analyser pour les modes debug
            pages_debug = [
                url,
                f"{url}/.env",
                f"{url}/phpinfo.php",
                f"{url}/server-status",
                f"{url}/server-info",
                f"{url}/debug",
                f"{url}/trace.axd",
                f"{url}/elmah.axd"
            ]

            async with aiohttp.ClientSession() as session:
                for page_url in pages_debug:
                    try:
                        async with session.get(
                            page_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            allow_redirects=False
                        ) as response:

                            if response.status == 200:
                                contenu = await response.text()

                                # Vérifier les patterns de debug selon les technologies
                                for tech, patterns in self.debug_patterns.items():
                                    if any(t in tech_keys for t in ['php', 'asp', 'net', 'java', 'javascript', 'node']):
                                        for pattern in patterns:
                                            if re.search(pattern, contenu, re.IGNORECASE):
                                                vuln = Vulnerabilite(
                                                    type=f"Mode debug activé: {tech.upper()}",
                                                    severite="MOYEN",
                                                    url=page_url,
                                                    description=f"Mode debug/développement activé pour {tech}",
                                                    payload=f"Pattern: {pattern}",
                                                    preuve="Informations de debug exposées",
                                                    cvss_score=5.3,
                                                    remediation="Désactiver les modes debug et supprimer les informations sensibles en production"
                                                )
                                                vulnerabilites.append(vuln)
                                                break

                                # Vérifications spécifiques
                                if 'phpinfo' in contenu.lower() and 'php version' in contenu.lower():
                                    vuln = Vulnerabilite(
                                        type="PHP Debug: phpinfo() exposé",
                                        severite="ÉLEVÉ",
                                        url=page_url,
                                        description="Page phpinfo() accessible exposant des informations sensibles",
                                        payload="phpinfo() function output",
                                        preuve="Informations système PHP exposées",
                                        cvss_score=7.5,
                                        remediation="Supprimer les fichiers phpinfo.php et autres pages de debug en production"
                                    )
                                    vulnerabilites.append(vuln)

                    except:
                        continue

        except Exception as e:
            logger.debug(f"Erreur analyse modes debug: {str(e)}")

        return vulnerabilites

    async def _analyser_credentials_defaut(self, url: str, technologies: Dict[str, str]) -> List[Vulnerabilite]:
        """Analyse les utilisations de credentials par défaut"""
        vulnerabilites = []

        try:
            # Chercher les formulaires de login
            login_urls = [
                f"{url}/login",
                f"{url}/admin/login",
                f"{url}/auth/login",
                f"{url}/api/auth/login"
            ]

            async with aiohttp.ClientSession() as session:
                for login_url in login_urls:
                    for username, passwords in self.default_credentials.items():
                        for password in passwords:
                            try:
                                data = {'username': username, 'password': password}
                                if 'admin' in login_url or 'auth' in login_url:
                                    data = {'user': username, 'pass': password}

                                async with session.post(
                                    login_url,
                                    data=data,
                                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                                    allow_redirects=False
                                ) as response:

                                    contenu = await response.text()

                                    # Vérifier signes de succès
                                    signes_succes = [
                                        'dashboard', 'welcome', 'logged in', 'success',
                                        'admin panel', 'control panel', 'redirect'
                                    ]

                                    if response.status in [200, 302, 301] and \
                                       any(s in contenu.lower() for s in signes_succes):

                                        vuln = Vulnerabilite(
                                            type="Credentials par défaut",
                                            severite="CRITIQUE",
                                            url=login_url,
                                            description="Authentification réussie avec des credentials par défaut",
                                            payload=f"{username}:{password}",
                                            preuve=f"Login réussi avec credentials par défaut: {username}/{password}",
                                            cvss_score=9.8,
                                            remediation="Changer immédiatement tous les mots de passe par défaut et utiliser des mots de passe forts"
                                        )
                                        vulnerabilites.append(vuln)
                                        break

                                # Délai pour éviter les bans
                                await asyncio.sleep(1)

                            except:
                                continue

        except Exception as e:
            logger.debug(f"Erreur analyse credentials défaut: {str(e)}")

        return vulnerabilites

    async def _analyser_fichiers_sensibles(self, url: str) -> List[Vulnerabilite]:
        """Analyse les fichiers sensibles exposés"""
        vulnerabilites = []

        try:
            # Fichiers sensibles courants à vérifier
            fichiers_sensibles = [
                '.env', '.git/config', '.git/HEAD', '.svn/entries',
                'config.php', 'settings.php', 'database.php', 'db.php',
                'web.config', 'appsettings.json', 'application.properties',
                'server.xml', 'context.xml', 'wp-config.php',
                'configuration.php', 'config.inc.php', 'backup.sql',
                'dump.sql', 'database.sql', 'users.sql'
            ]

            async with aiohttp.ClientSession() as session:
                for fichier in fichiers_sensibles:
                    try:
                        file_url = f"{url}/{fichier}"
                        async with session.get(
                            file_url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            allow_redirects=False
                        ) as response:

                            if response.status == 200:
                                contenu = await response.text()

                                # Analyser le contenu selon le type de fichier
                                if fichier == '.env':
                                    if any(keyword in contenu for keyword in ['DB_PASSWORD', 'SECRET_KEY', 'API_KEY']):
                                        vuln = Vulnerabilite(
                                            type="Fichier sensible exposé: .env",
                                            severite="CRITIQUE",
                                            url=file_url,
                                            description="Fichier .env contenant des secrets exposé",
                                            payload="Variables d'environnement sensibles",
                                            preuve="Fichier .env accessible publiquement",
                                            cvss_score=9.8,
                                            remediation="Ne jamais commiter ou exposer les fichiers .env en production"
                                        )
                                        vulnerabilites.append(vuln)

                                elif 'config' in fichier and 'password' in contenu.lower():
                                    vuln = Vulnerabilite(
                                        type=f"Fichier de configuration exposé: {fichier}",
                                        severite="ÉLEVÉ",
                                        url=file_url,
                                        description=f"Fichier de configuration {fichier} contenant des mots de passe exposé",
                                        payload="Informations de configuration sensibles",
                                        preuve="Fichier de config avec mots de passe accessible",
                                        cvss_score=7.5,
                                        remediation="Protéger les fichiers de configuration et chiffrer les mots de passe"
                                    )
                                    vulnerabilites.append(vuln)

                                elif fichier.endswith('.sql'):
                                    vuln = Vulnerabilite(
                                        type="Dump de base de données exposé",
                                        severite="CRITIQUE",
                                        url=file_url,
                                        description="Fichier de dump/base de données SQL exposé",
                                        payload="Données sensibles dans dump SQL",
                                        preuve="Fichier SQL accessible publiquement",
                                        cvss_score=9.8,
                                        remediation="Supprimer immédiatement les dumps de base de données du serveur web"
                                    )
                                    vulnerabilites.append(vuln)

                    except:
                        continue

        except Exception as e:
            logger.debug(f"Erreur analyse fichiers sensibles: {str(e)}")

        return vulnerabilites

    def _generer_noms_buckets_potentiels(self, domaine: str) -> List[str]:
        """Génère des noms de buckets S3 potentiels"""
        base = domaine.replace('.', '-')
        return [
            base,
            f"{base}-backup",
            f"{base}-storage",
            f"{base}-files",
            f"{base}-uploads",
            f"{base}-assets",
            f"{base}-media",
            f"{base}-static"
        ]

    def _generer_noms_azure_potentiels(self, domaine: str) -> List[str]:
        """Génère des noms de comptes Azure potentiels"""
        base = domaine.replace('.', '')
        return [
            base,
            f"{base}storage",
            f"{base}files",
            f"{base}backup",
            f"{base}assets"
        ]

    def _est_bucket_prive(self, contenu: str) -> bool:
        """Vérifie si un bucket S3 semble privé"""
        indicateurs_prives = [
            'accessdenied',
            'access denied',
            '403 forbidden',
            'no such bucket',
            'bucket does not exist'
        ]
        return any(indicateur in contenu.lower() for indicateur in indicateurs_prives)

    def _dedupliquer_vulnerabilites(self, vulnerabilites: List[Vulnerabilite]) -> List[Vulnerabilite]:
        """Élimine les vulnérabilités en double"""
        vues = {}

        for vuln in vulnerabilites:
            cle = f"{vuln.type}:{vuln.url}"
            if cle not in vues:
                vues[cle] = vuln

        return list(vues.values())
