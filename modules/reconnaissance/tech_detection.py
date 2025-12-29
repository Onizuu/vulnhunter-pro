"""
Détecteur de technologies web avancé
Détecte versions précises, frameworks, bases de données, CDN, etc.
"""

import asyncio
from typing import Dict, List, Tuple
from loguru import logger
import aiohttp
import re
import json


class DetecteurTechnologies:
    """
    Détecteur avancé de technologies web avec versions précises
    """

    def __init__(self):
        # Patterns étendus avec expressions régulières pour versions
        self.patterns = {
            # Langages de programmation
            'PHP': [
                (r'X-Powered-By: PHP/([\d.]+)', 'version'),
                (r'PHP/([\d.]+)', 'version'),
                (r'phpinfo\(\)', 'function'),
                (r'\.php', 'extension'),
            ],
            'Node.js': [
                (r'X-Powered-By: Node\.js v?([\d.]+)', 'version'),
                (r'node\.js', 'mention'),
                (r'nodejs', 'mention'),
            ],
            'Python': [
                (r'Python/([\d.]+)', 'version'),
                (r'Django', 'framework'),
                (r'Flask', 'framework'),
                (r'FastAPI', 'framework'),
            ],
            'Ruby': [
                (r'Ruby/([\d.]+)', 'version'),
                (r'Rails', 'framework'),
            ],
            'Java': [
                (r'Java/([\d.]+)', 'version'),
                (r'JSP', 'technology'),
                (r'Spring', 'framework'),
            ],
            'Go': [
                (r'Go/([\d.]+)', 'version'),
                (r'golang', 'mention'),
            ],
            '.NET': [
                (r'X-AspNet-Version: ([\d.]+)', 'version'),
                (r'ASP\.NET', 'framework'),
                (r'\.aspx', 'extension'),
            ],

            # Frameworks Frontend
            'React': [
                (r'react@([\d.]+)', 'version'),
                (r'react\.js', 'library'),
                (r'_react', 'internal'),
                (r'__REACT_DEVTOOLS', 'devtool'),
            ],
            'Vue.js': [
                (r'vue@([\d.]+)', 'version'),
                (r'vue\.js', 'library'),
                (r'_vue', 'internal'),
            ],
            'Angular': [
                (r'angular@([\d.]+)', 'version'),
                (r'ng-app', 'directive'),
                (r'angular\.js', 'library'),
            ],
            'jQuery': [
                (r'jquery@([\d.]+)', 'version'),
                (r'jquery-([\d.]+)\.js', 'version'),
                (r'jQuery v([\d.]+)', 'version'),
            ],
            'Bootstrap': [
                (r'bootstrap@([\d.]+)', 'version'),
                (r'bootstrap\.css', 'library'),
            ],

            # Frameworks Backend
            'Express': [
                (r'X-Powered-By: Express', 'header'),
                (r'express@([\d.]+)', 'version'),
            ],
            'Django': [
                (r'csrfmiddlewaretoken', 'token'),
                (r'django', 'mention'),
                (r'Django/([\d.]+)', 'version'),
            ],
            'Laravel': [
                (r'laravel_session', 'session'),
                (r'Laravel', 'framework'),
                (r'laravel@([\d.]+)', 'version'),
            ],
            'Spring Boot': [
                (r'Spring Boot', 'framework'),
                (r'spring-boot', 'mention'),
            ],

            # Serveurs Web
            'Apache': [
                (r'Server: Apache/([\d.]+)', 'version'),
                (r'Apache/([\d.]+)', 'version'),
                (r'mod_', 'module'),
            ],
            'Nginx': [
                (r'Server: nginx/([\d.]+)', 'version'),
                (r'nginx/([\d.]+)', 'version'),
            ],
            'IIS': [
                (r'Server: Microsoft-IIS/([\d.]+)', 'version'),
                (r'Microsoft-IIS', 'server'),
            ],
            'LiteSpeed': [
                (r'Server: LiteSpeed', 'server'),
            ],

            # Bases de données
            'MySQL': [
                (r'mysql', 'mention'),
                (r'MySQL', 'database'),
                (r'phpmyadmin', 'admin'),
            ],
            'PostgreSQL': [
                (r'postgresql', 'database'),
                (r'postgres', 'database'),
            ],
            'MongoDB': [
                (r'mongodb', 'database'),
                (r'MongoDB', 'database'),
            ],
            'Redis': [
                (r'redis', 'database'),
            ],

            # Systèmes de gestion de contenu
            'WordPress': [
                (r'/wp-content/', 'path'),
                (r'/wp-includes/', 'path'),
                (r'WordPress', 'cms'),
                (r'wp-json', 'api'),
            ],
            'Joomla': [
                (r'/components/com_', 'path'),
                (r'Joomla', 'cms'),
            ],
            'Drupal': [
                (r'Drupal', 'cms'),
                (r'/sites/default/', 'path'),
            ],

            # CDN et Services
            'Cloudflare': [
                (r'__cfduid', 'cookie'),
                (r'cloudflare', 'service'),
                (r'CF-RAY', 'header'),
            ],
            'AWS': [
                (r'amazonaws\.com', 'domain'),
                (r'aws', 'service'),
            ],
            'Azure': [
                (r'azure', 'service'),
                (r'windows\.net', 'domain'),
            ],
            'Google Cloud': [
                (r'googleusercontent\.com', 'domain'),
                (r'gcp', 'service'),
            ],

            # Sécurité
            'ModSecurity': [
                (r'ModSecurity', 'waf'),
                (r'mod_security', 'waf'),
            ],
            'Cloudflare WAF': [
                (r'__cf_chl_jschl_tk__', 'challenge'),
            ],

            # Outils de développement
            'Webpack': [
                (r'webpack', 'bundler'),
            ],
            'Vite': [
                (r'vite', 'bundler'),
            ],
            'Babel': [
                (r'babel', 'transpiler'),
            ],
        }

        # Patterns pour l'extraction de versions depuis les URLs
        self.version_patterns = {
            'jquery': r'jquery[.-]([\d.]+)',
            'bootstrap': r'bootstrap[.-]([\d.]+)',
            'react': r'react[.-]([\d.]+)',
            'vue': r'vue[.-]([\d.]+)',
            'angular': r'angular[.-]([\d.]+)',
        }

    async def detecter(self, url: str, verify_ssl: bool = True) -> Dict[str, str]:
        """
        Détecte les technologies utilisées avec versions précises

        Args:
            url: URL à analyser
            verify_ssl: Vérifier les certificats SSL (défaut: True)

        Returns:
            Dict[str, str]: Technologies détectées avec versions
        """
        technologies = {}

        try:
            logger.info(f"🔍 Détection technologies avancée: {url}")

            connector = aiohttp.TCPConnector(verify_ssl=verify_ssl)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    contenu = await response.text()
                    headers = dict(response.headers)

                    # Analyser tous les patterns avancés
                    for tech, patterns in self.patterns.items():
                        for pattern_tuple in patterns:
                            if isinstance(pattern_tuple, tuple):
                                pattern, detection_type = pattern_tuple
                            else:
                                pattern = pattern_tuple
                                detection_type = 'unknown'

                            version = None

                            # Chercher dans headers avec capture de version
                            for header_name, header_value in headers.items():
                                full_header = f"{header_name}: {header_value}"
                                match = re.search(pattern, full_header, re.IGNORECASE)
                                if match:
                                    if len(match.groups()) > 0:
                                        version = match.group(1)
                                    technologies[tech] = f"v{version}" if version else f"détecté ({detection_type})"
                                    break

                            # Chercher dans le contenu avec capture de version
                            if tech not in technologies:
                                match = re.search(pattern, contenu, re.IGNORECASE)
                                if match:
                                    if len(match.groups()) > 0:
                                        version = match.group(1)
                                    technologies[tech] = f"v{version}" if version else f"détecté ({detection_type})"

                    # Détection spéciale pour les frameworks JavaScript
                    technologies.update(self._detecter_js_frameworks(contenu))

                    # Détection des versions depuis les URLs dans le contenu
                    technologies.update(self._detecter_versions_url(contenu))

                    # Informations serveur détaillées
                    technologies.update(self._analyser_headers_serveur(headers))

                    # Détection CDN et services cloud
                    technologies.update(self._detecter_services_cloud(headers, contenu))

            # Nettoyer et formater les résultats
            technologies = self._nettoyer_resultats(technologies)

            logger.info(f"✅ {len(technologies)} technologies détectées avec versions")

            # Afficher un résumé détaillé
            self._afficher_resume_detaille(technologies)

            return technologies

        except Exception as e:
            logger.error(f"Erreur détection tech avancée: {str(e)}")
            return {}

    def _detecter_js_frameworks(self, contenu: str) -> Dict[str, str]:
        """Détection spécialisée des frameworks JavaScript"""
        frameworks = {}

        # React - chercher la version dans les scripts
        react_match = re.search(r'("version":\s*"([^"]*react[^"]*)")', contenu, re.IGNORECASE)
        if react_match:
            frameworks['React'] = f"v{react_match.group(2)}"

        # Vue.js - chercher dans les scripts
        vue_match = re.search(r'("version":\s*"([^"]*vue[^"]*)")', contenu, re.IGNORECASE)
        if vue_match:
            frameworks['Vue.js'] = f"v{vue_match.group(2)}"

        # Angular - chercher dans les scripts
        angular_match = re.search(r'("version":\s*"([^"]*angular[^"]*)")', contenu, re.IGNORECASE)
        if angular_match:
            frameworks['Angular'] = f"v{angular_match.group(2)}"

        return frameworks

    def _detecter_versions_url(self, contenu: str) -> Dict[str, str]:
        """Extrait les versions depuis les URLs dans le HTML"""
        versions = {}

        for lib, pattern in self.version_patterns.items():
            matches = re.findall(pattern, contenu, re.IGNORECASE)
            if matches:
                # Prendre la version la plus récente
                versions[lib.title()] = f"v{max(matches)}"

        return versions

    def _analyser_headers_serveur(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Analyse détaillée des headers serveur"""
        serveur_info = {}

        # Server header détaillé
        if 'Server' in headers:
            server = headers['Server']
            serveur_info['Serveur Web'] = server

            # Extraire version depuis Server header
            if 'Apache' in server:
                version_match = re.search(r'Apache/([\d.]+)', server)
                if version_match:
                    serveur_info['Apache'] = f"v{version_match.group(1)}"
            elif 'nginx' in server:
                version_match = re.search(r'nginx/([\d.]+)', server)
                if version_match:
                    serveur_info['Nginx'] = f"v{version_match.group(1)}"
            elif 'Microsoft-IIS' in server:
                version_match = re.search(r'Microsoft-IIS/([\d.]+)', server)
                if version_match:
                    serveur_info['IIS'] = f"v{version_match.group(1)}"

        # X-Powered-By détaillé
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            serveur_info['Backend'] = powered_by

            # Extraire versions depuis X-Powered-By
            if 'PHP' in powered_by:
                version_match = re.search(r'PHP/([\d.]+)', powered_by)
                if version_match:
                    serveur_info['PHP'] = f"v{version_match.group(1)}"
            elif 'Express' in powered_by:
                serveur_info['Express'] = "détecté"
            elif 'ASP.NET' in powered_by:
                serveur_info['ASP.NET'] = "détecté"

        return serveur_info

    def _detecter_services_cloud(self, headers: Dict[str, str], contenu: str) -> Dict[str, str]:
        """Détection des services cloud et CDN"""
        services = {}

        # Cloudflare
        if any(h.lower() in ['cf-ray', 'cf-cache-status', 'cf-request-id'] for h in headers.keys()):
            services['Cloudflare'] = 'CDN/WAF détecté'
        elif '__cfduid' in str(headers).lower():
            services['Cloudflare'] = 'CDN détecté'

        # AWS
        if 'amazonaws.com' in contenu or 'aws' in str(headers).lower():
            services['AWS'] = 'Service cloud détecté'

        # Azure
        if 'azure' in contenu.lower() or 'windows.net' in contenu:
            services['Azure'] = 'Service cloud détecté'

        # Google Cloud
        if 'googleusercontent.com' in contenu or 'gcp' in contenu.lower():
            services['Google Cloud'] = 'Service cloud détecté'

        return services

    def _nettoyer_resultats(self, technologies: Dict[str, str]) -> Dict[str, str]:
        """Nettoie et formate les résultats"""
        nettoye = {}

        for tech, info in technologies.items():
            # Éviter les doublons et nettoyer
            if tech not in nettoye:
                # Nettoyer les informations de détection
                if 'détecté (' in info:
                    info = info.split('détecté (')[0] + 'détecté'

                nettoye[tech] = info

        return nettoye

    def _afficher_resume_detaille(self, technologies: Dict[str, str]):
        """Affiche un résumé détaillé des technologies détectées"""
        if not technologies:
            logger.info("ℹ️  Aucune technologie détectée")
            return

        logger.info("📊 Technologies détectées:")

        # Grouper par catégorie
        categories = {
            'Langages': ['PHP', 'Node.js', 'Python', 'Ruby', 'Java', 'Go', '.NET'],
            'Frontend': ['React', 'Vue.js', 'Angular', 'jQuery', 'Bootstrap'],
            'Backend': ['Express', 'Django', 'Laravel', 'Spring Boot'],
            'Serveurs': ['Apache', 'Nginx', 'IIS', 'LiteSpeed', 'Serveur Web'],
            'Base de données': ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis'],
            'CMS': ['WordPress', 'Joomla', 'Drupal'],
            'Services': ['Cloudflare', 'AWS', 'Azure', 'Google Cloud'],
            'Sécurité': ['ModSecurity', 'Cloudflare WAF'],
            'Outils': ['Webpack', 'Vite', 'Babel']
        }

        for categorie, techs in categories.items():
            trouvees = {k: v for k, v in technologies.items() if k in techs}
            if trouvees:
                logger.info(f"  {categorie}: {', '.join([f'{k} {v}' for k, v in trouvees.items()])}")

        autres = {k: v for k, v in technologies.items() if not any(k in cat for cat in categories.values())}
        if autres:
            logger.info(f"  Autres: {', '.join([f'{k} {v}' for k, v in autres.items()])}")

